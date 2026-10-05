#!/usr/bin/env python3
"""
=============================================================================
analise_unidades.py — Anomalias por secretaria (T18, cap. 5)
=============================================================================
Aplica o modelo treinado ao tráfego da semana e compara as secretarias por
TAXA (anomalias por 10 mil registros), e não por contagem absoluta: sem a
normalização, a secretaria de maior tráfego sempre pareceria "a mais atacada".

  * Pontua uma amostra aleatória de cada arquivo (--max-por-arquivo); a taxa
    vem com intervalo de confiança de 95% (Wilson), o que mostra se a
    diferença entre secretarias é maior que o erro da amostragem.
  * Exclui os ataques controlados (reais e injetados) e o tráfego da origem de
    cada ataque no mesmo dia (janelas contaminadas): a análise é sobre o
    tráfego ORDINÁRIO de cada secretaria.
  * "Só ML": fração das anomalias em que o firewall não sinalizou nada.
  * Todas as saídas saem anonimizadas (Secretaria A, B, C; Roteador 1, 2);
    nenhuma contém IP ou MAC.

Saídas (em --out):
  por_unidade.csv, por_unidade_direcao.csv, por_unidade_hora.csv,
  por_unidade_modelo.csv, portas_anomalas.csv, resumo.json,
  fig_taxa_unidade.png, fig_taxa_hora.png

Uso:
  python analise_unidades.py --bundle modelos/bundle.joblib \\
         --parquet "pq/*.parquet" --ataques ataques.csv --out analise
=============================================================================
"""
import argparse, glob, json, math, os, time
import numpy as np
import polars as pl
import joblib

import common_features_polars as cf
import models as M  # noqa: F401  (necessário para o joblib reconstruir os detectores)


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def taxa_tab(df, by, n_total_by=None):
    """Taxa por 10 mil registros, com IC 95%, para cada grupo."""
    g = (df.group_by(by).agg([pl.len().alias("registros_amostra"),
                              pl.col("anomalo").sum().alias("anomalos"),
                              (pl.col("anomalo") * (1 - pl.col("fw_flag"))).sum().alias("anomalos_so_ml")])
           .sort(by))
    rows = []
    for r in g.iter_rows(named=True):
        lo, hi = wilson(r["anomalos"], r["registros_amostra"])
        rows.append({**r,
                     "taxa_por_10k": 1e4 * r["anomalos"] / max(r["registros_amostra"], 1),
                     "ic95_inf": 1e4 * lo, "ic95_sup": 1e4 * hi,
                     "fracao_so_ml": (r["anomalos_so_ml"] / r["anomalos"]) if r["anomalos"] else None})
    out = pl.DataFrame(rows)
    if n_total_by is not None:
        out = out.join(n_total_by, on=by, how="left")
    return out.with_columns([pl.col(c).round(3) for c in ("taxa_por_10k", "ic95_inf", "ic95_sup")]
                            + [pl.col("fracao_so_ml").round(3)])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--parquet", required=True)
    ap.add_argument("--ataques", help="CSV de ground truth (para excluir os ataques controlados)")
    ap.add_argument("--out", default="analise")
    ap.add_argument("--max-por-arquivo", type=int, default=300_000)
    ap.add_argument("--semente", type=int, default=7)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    b = joblib.load(a.bundle)
    dets = b["detectors"]
    min_votes = b["min_votes"]
    aw = cf.read_attack_windows(a.ataques) if a.ataques else None
    paths = sorted(glob.glob(a.parquet))
    if not paths:
        raise SystemExit(f"nenhum Parquet em {a.parquet}")

    partes, totais = [], []
    t0 = time.time()
    for p in paths:
        df = pl.read_parquet(p)
        if aw is not None:
            df = cf.label_ground_truth(df, aw)
            contam = pl.lit(False)
            for w in aw.iter_rows(named=True):
                contam = contam | ((pl.col("src_ip") == w["src_ip"])
                                   & (pl.col("dt") >= w["start"])
                                   & (pl.col("dt").dt.date() == w["end"].date()))
            df = df.filter((pl.col("is_atk") == 0) & ~contam)
        totais.append(df.group_by(["hostname", "unidade"]).len().rename({"len": "registros_total"})
                        .filter(~pl.col("unidade").is_in(list(cf.UNIT_FORA_COMPARACAO))))
        if df.height > a.max_por_arquivo:
            df = df.sample(a.max_por_arquivo, seed=a.semente)
        X, feats, _ = cf.build_features(df, encoders=b["encoders"], windows=b["windows"],
                                        verbose=False)
        if feats != b["features"]:
            raise SystemExit("lista de features difere da do treino (re-exporte os Parquet)")
        Xs = b["scaler"].transform(X).astype(np.float32)
        preds = {n: d.predict(Xs) for n, d in dets.items()}
        votes = np.sum(np.vstack(list(preds.values())), axis=0)
        partes.append(df.select(["hostname", "unidade", "direcao", "dt", "dst_port", "protocol",
                                 "src_ip", "fw_flag"])
                        .with_columns([pl.Series(f"pred_{n}", v) for n, v in preds.items()]
                                      + [pl.Series("votos", votes.astype(np.int8)),
                                         pl.Series("anomalo", (votes >= min_votes).astype(np.int8))]))
        print(f"  {os.path.basename(p)}: {df.height:,} registros pontuados "
              f"({time.time() - t0:.0f} s acumulados)")

    d = pl.concat(partes)
    fora = d.filter(pl.col("unidade").is_in(list(cf.UNIT_FORA_COMPARACAO))
                    | pl.col("unidade").str.ends_with("(roteador)"))
    print(f"  Fora da comparação entre secretarias (infraestrutura e tráfego ao roteador): "
          f"{fora.height:,} registros pontuados")
    d = d.filter(~(pl.col("unidade").is_in(list(cf.UNIT_FORA_COMPARACAO))
                   | pl.col("unidade").str.ends_with("(roteador)")))
    d = d.with_columns(pl.col("dt").dt.hour().alias("hora"),
                                       pl.col("fw_flag").cast(pl.Int64),
                                       pl.col("anomalo").cast(pl.Int64))
    tot = (pl.concat(totais).group_by(["hostname", "unidade"]).agg(pl.col("registros_total").sum()))

    # ---------------------------------------------------------------- tabelas
    t_uni = taxa_tab(d, ["hostname", "unidade"], tot)
    orig = (d.filter(pl.col("anomalo") == 1).group_by(["hostname", "unidade"])
              .agg(pl.col("src_ip").n_unique().alias("origens_distintas_anomalas")))
    t_uni = t_uni.join(orig, on=["hostname", "unidade"], how="left")
    t_dir = taxa_tab(d, ["unidade", "direcao"])
    t_hora = taxa_tab(d, ["unidade", "hora"])
    mod_rows = []
    for n in dets:
        g = d.group_by("unidade").agg([pl.len().alias("n"), pl.col(f"pred_{n}").sum().alias("k")])
        for r in g.iter_rows(named=True):
            mod_rows.append({"modelo": n, "unidade": r["unidade"],
                             "taxa_por_10k": round(1e4 * r["k"] / r["n"], 3)})
    t_mod = pl.DataFrame(mod_rows).sort(["unidade", "modelo"])
    portas = (d.filter(pl.col("anomalo") == 1)
               .group_by(["unidade", "protocol", "dst_port"]).len()
               .sort(["unidade", "len"], descending=[False, True])
               .group_by("unidade", maintain_order=True).head(10)
               .rename({"len": "registros_anomalos"}))

    saidas = {"por_unidade": t_uni, "por_unidade_direcao": t_dir, "por_unidade_hora": t_hora,
              "por_unidade_modelo": t_mod, "portas_anomalas": portas}
    for nome, t in saidas.items():
        cf.anonymize(t).write_csv(os.path.join(a.out, f"{nome}.csv"))

    resumo = {
        "arquivos": len(paths), "registros_pontuados": d.height,
        "registros_total_sem_ataques": int(tot["registros_total"].sum()),
        "anomalos_na_amostra": int(d["anomalo"].sum()),
        "taxa_geral_por_10k": round(1e4 * d["anomalo"].sum() / d.height, 3),
        "fracao_so_ml_geral": round(float((d["anomalo"] * (1 - d["fw_flag"])).sum()
                                          / max(d["anomalo"].sum(), 1)), 3),
        "min_votos": min_votes, "amostra_max_por_arquivo": a.max_por_arquivo,
        "ataques_controlados_excluidos": aw is not None,
    }
    json.dump(resumo, open(os.path.join(a.out, "resumo.json"), "w"), indent=2, ensure_ascii=False)

    # ---------------------------------------------------------------- figuras
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    ta = cf.anonymize(t_uni).sort("unidade")
    fig, ax = plt.subplots(figsize=(7, 3.8))
    x = np.arange(ta.height)
    y = ta["taxa_por_10k"].to_numpy()
    err = np.vstack([y - ta["ic95_inf"].to_numpy(), ta["ic95_sup"].to_numpy() - y])
    ax.bar(x, y, color="#2f6fb3", alpha=0.85)
    ax.errorbar(x, y, yerr=err, fmt="none", ecolor="#24303c", capsize=4, lw=1.2)
    ax.set_xticks(x, ta["unidade"].to_list())
    ax.set_ylabel("Anomalias por 10 mil registros")
    ax.grid(axis="y", alpha=0.3)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(os.path.join(a.out, "fig_taxa_unidade.png"), dpi=200)
    plt.close(fig)

    th = cf.anonymize(t_hora)
    fig, ax = plt.subplots(figsize=(8, 3.8))
    for (u,), g in th.sort("hora").group_by(["unidade"], maintain_order=True):
        ax.plot(g["hora"], g["taxa_por_10k"], marker="o", ms=3, lw=1.5, label=u)
    ax.set_xlabel("Hora do dia")
    ax.set_ylabel("Anomalias por 10 mil registros")
    ax.set_xticks(range(0, 24, 2))
    ax.grid(alpha=0.3)
    ax.legend(frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(os.path.join(a.out, "fig_taxa_hora.png"), dpi=200)
    plt.close(fig)

    print(f"\nTaxa geral: {resumo['taxa_geral_por_10k']} por 10 mil | "
          f"só ML: {100*resumo['fracao_so_ml_geral']:.1f}% | saídas em {a.out}/")
    with pl.Config(tbl_cols=12, tbl_width_chars=150):
        print(cf.anonymize(t_uni))


if __name__ == "__main__":
    main()
