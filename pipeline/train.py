#!/usr/bin/env python3
"""
=============================================================================
train.py — Treino e avaliação dos 5 detectores + ensemble (item 5.2 do TCC)
=============================================================================
Fluxo:
  1. Amostra estratificada dos Parquet (export_to_parquet), preservando os
     eventos de ataque e as linhas sinalizadas pelo firewall.
  2. Treino = tráfego normal (fw_flag=0 e is_atk=0), 80% da amostra normal.
     Teste  = os outros 20% do normal + todos os eventos de ataque rotulados.
  3. Encoders e padronização ajustados SÓ no treino.
  4. Cada detector: treino, limiar fixado no percentil q dos escores de
     treino (sem olhar o ground truth), pontuação do teste.
     Algoritmos com componente aleatório: várias sementes (média ± dp).
  5. Métricas: precisão, recall e F1 por registro; recall por EVENTO;
     por regime (acima/abaixo do limiar) e origem (real/sintético);
     comparação com a detecção do firewall; alertas estimados por dia;
     tempos de treino e de inferência.
  6. Salva bundle.joblib (modelos, scaler, encoders, limiares, conjunto de
     verificação) para test_inference.py e realtime_scanner.py.

Uso:
  python train.py --parquet "pq/*.parquet" --ataques ataques.csv --out modelos
  python train.py ... --device cpu --seeds 3 --n-sample 1000000
=============================================================================
"""
import argparse, glob, json, os, platform, time
import numpy as np
import polars as pl
import joblib
from sklearn.preprocessing import StandardScaler

import common_features_polars as cf
import models as M


def parse_args():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--parquet", required=True, help='glob, ex. "pq/*.parquet"')
    p.add_argument("--ataques", help="CSV start,end,src_ip,regime,origem,tipo")
    p.add_argument("--out", default="modelos")
    p.add_argument("--n-sample", type=float, default=3e6)
    p.add_argument("--test-frac", type=float, default=0.2,
                   help="fração do normal reservada para teste")
    p.add_argument("--q", type=float, default=99.5,
                   help="percentil dos escores de treino usado como limiar")
    p.add_argument("--seeds", type=int, default=5)
    p.add_argument("--device", default="auto", choices=["auto", "cpu", "gpu"])
    p.add_argument("--models", default=",".join(M.MODEL_NAMES))
    p.add_argument("--min-votes", type=int, default=3)
    p.add_argument("--ocsvm-impl", default="nystroem", choices=["nystroem", "thundersvm"])
    p.add_argument("--max-fit-lof", type=int, default=500_000)
    p.add_argument("--max-fit-dbscan", type=int, default=200_000)
    p.add_argument("--max-cal", type=int, default=300_000,
                   help="nº de registros de treino usados para fixar o limiar")
    return p.parse_args()


# --------------------------------------------------------------------------
def metrics(pred, test, n_normal_day):
    """pred: 0/1 por registro do teste. test: DataFrame polars do teste."""
    y = test["is_atk"].to_numpy().astype(bool)
    p = pred.astype(bool)
    vp, fp, fn = int((p & y).sum()), int((p & ~y).sum()), int((~p & y).sum())
    prec = vp / (vp + fp) if vp + fp else 0.0
    rec = vp / (vp + fn) if vp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fpr = fp / max((~y).sum(), 1)
    ev = (test.with_columns(pl.Series("_p", pred))
              .filter(pl.col("is_atk") == 1)
              .group_by("atk_evento").agg(pl.col("_p").max().alias("det")))
    rec_ev = float(ev["det"].mean()) if ev.height else float("nan")
    return {"precisao": prec, "recall_reg": rec, "f1": f1, "recall_evento": rec_ev,
            "fpr": fpr, "alertas_dia": fpr * n_normal_day, "vp": vp, "fp": fp, "fn": fn}


def per_event(pred, test):
    """Detecção por evento: modelo x firewall, com regime/origem/tipo."""
    extra = [c for c in test.columns if c.startswith("atk_") and c != "atk_evento"]
    return (test.with_columns(pl.Series("_p", pred))
                .filter(pl.col("is_atk") == 1)
                .group_by(["atk_evento"] + extra)
                .agg([pl.col("_p").max().alias("modelo"),
                      pl.col("fw_flag").max().alias("firewall"),
                      pl.len().alias("registros")])
                .sort("atk_evento"))


# --------------------------------------------------------------------------
def main():
    a = parse_args()
    os.makedirs(a.out, exist_ok=True)
    names = [m.strip() for m in a.models.split(",") if m.strip()]
    print("Backends:", M.backend_report())

    # 1. dados ----------------------------------------------------------------
    paths = sorted(glob.glob(a.parquet))
    if not paths:
        raise SystemExit(f"nenhum Parquet em {a.parquet}")
    aw = cf.read_attack_windows(a.ataques) if a.ataques else None
    total = sum(pl.scan_parquet(p).select(pl.len()).collect().item() for p in paths)
    n_days = (pl.scan_parquet(paths).select(pl.col("dt").dt.date().n_unique())
                .collect().item())
    sample = cf.stratified_sample(paths, int(a.n_sample), attack_windows=aw)
    if "atk_evento" not in sample.columns:
        sample = sample.with_columns(pl.lit(None, dtype=pl.Int32).alias("atk_evento"))

    # Registros da ORIGEM do ataque que não são o ataque em si (outros destinos
    # durante o evento, quando o CSV traz dst_ip, e qualquer tráfego depois do
    # fim, no mesmo dia) herdam contagens de janela infladas (a janela de 24 h
    # só zera à meia-noite). Não são ataque nem tráfego normal "limpo": ficam
    # fora do treino e do teste.
    contam = pl.lit(False)
    if aw is not None:
        for w in aw.iter_rows(named=True):
            contam = contam | ((pl.col("src_ip") == w["src_ip"])
                               & (pl.col("dt") >= w["start"])
                               & (pl.col("dt").dt.date() == w["end"].date())
                               & (pl.col("is_atk") == 0))
    sample = sample.with_columns(contam.alias("pos_ataque"))
    print(f"Registros pós-ataque excluídos: {int(sample['pos_ataque'].sum()):,}")
    sample = sample.filter(~pl.col("pos_ataque"))
    normal = sample.filter((pl.col("fw_flag") == 0) & (pl.col("is_atk") == 0))
    attacks = sample.filter(pl.col("is_atk") == 1)
    fw_only = sample.filter((pl.col("fw_flag") == 1) & (pl.col("is_atk") == 0))
    rng = np.random.default_rng(42)
    is_test = rng.random(normal.height) < a.test_frac
    train_df = normal.filter(pl.Series(~is_test))
    test_df = pl.concat([normal.filter(pl.Series(is_test)), attacks],
                        how="diagonal_relaxed")
    n_normal_day = total / max(n_days, 1)
    print(f"Total {total:,} linhas em {n_days} dia(s) | treino {train_df.height:,} | "
          f"teste {test_df.height:,} ({attacks.height:,} de ataque, "
          f"{attacks['atk_evento'].n_unique() if attacks.height else 0} eventos) | "
          f"só-firewall {fw_only.height:,}")

    # 2. features -------------------------------------------------------------
    X_tr, feats, _, enc = cf.build_features(train_df, return_encoders=True, verbose=False)
    X_te, _, _ = cf.build_features(test_df, encoders=enc, verbose=False)
    X_fw = cf.build_features(fw_only, encoders=enc, verbose=False)[0] if fw_only.height else None
    scaler = StandardScaler().fit(X_tr)
    tr = scaler.transform(X_tr).astype(np.float32)
    te = scaler.transform(X_te).astype(np.float32)
    fwx = scaler.transform(X_fw).astype(np.float32) if X_fw is not None else None
    cal = tr[rng.choice(tr.shape[0], min(a.max_cal, tr.shape[0]), replace=False)]
    print(f"{len(feats)} features | treino {tr.shape} | teste {te.shape}")

    params = {"lof": {"max_fit": a.max_fit_lof},
              "dbscan": {"max_fit": a.max_fit_dbscan},
              "ocsvm": {"impl": a.ocsvm_impl}}

    # 3. treino / avaliação ---------------------------------------------------
    rows, preds_by_seed, ev_tables, keep = [], {}, [], {}
    for name in names:
        seeds = [0] if name in M.DETERMINISTIC else list(range(a.seeds))
        for s in seeds:
            det = M.make_detector(name, device=a.device, seed=s, **params.get(name, {}))
            det.fit(tr).calibrate(cal, a.q)
            t = time.perf_counter()
            sc = det.score(te)
            t_inf = time.perf_counter() - t
            pr = det.predict(te, sc)
            m = metrics(pr, test_df, n_normal_day)
            m.update({"modelo": name, "semente": s, "backend": det.backend_,
                      "n_treino": det.n_fit_, "t_treino_s": det.fit_time_,
                      "t_inferencia_ms_por_10k": 1e4 * 1e3 * t_inf / te.shape[0],
                      "limiar": det.threshold_})
            if fwx is not None:
                m["concorda_firewall"] = float(det.predict(fwx).mean())
            rows.append(m)
            for k in (range(a.seeds) if name in M.DETERMINISTIC else [s]):
                preds_by_seed.setdefault(k, {})[name] = pr
            if s == 0:
                keep[name] = det
                ev_tables.append(per_event(pr, test_df).with_columns(
                    pl.lit(name).alias("detector")))
            print(f"  {det.describe():55s} seed={s} F1={m['f1']:.3f} "
                  f"rec_ev={m['recall_evento']:.2f} alertas/dia={m['alertas_dia']:,.0f} "
                  f"treino={det.fit_time_:.1f}s")

    # ensemble (por semente)
    for s, pd_ in sorted(preds_by_seed.items()):
        if len(pd_) < len(names):
            continue
        votes = M.ensemble_votes(pd_)
        pr = (votes >= a.min_votes).astype(np.int8)
        m = metrics(pr, test_df, n_normal_day)
        m.update({"modelo": f"ensemble>={a.min_votes}", "semente": s, "backend": "-"})
        rows.append(m)
        if s == 0:
            ev_tables.append(per_event(pr, test_df).with_columns(
                pl.lit(m["modelo"]).alias("detector")))

    # 4. resultados -----------------------------------------------------------
    res = pl.DataFrame(rows)
    res.write_csv(os.path.join(a.out, "metricas_por_semente.csv"))
    num = ["precisao", "recall_reg", "recall_evento", "f1", "alertas_dia"]
    resumo = (res.group_by("modelo")
                 .agg([pl.col(c).mean().round(4).alias(c) for c in num]
                      + [pl.col("f1").std().round(4).alias("f1_dp"),
                         pl.col("t_treino_s").mean().round(2).alias("t_treino_s"),
                         pl.col("t_inferencia_ms_por_10k").mean().round(2)
                           .alias("t_inf_ms_10k")])
                 .sort("f1", descending=True))
    resumo.write_csv(os.path.join(a.out, "metricas_resumo.csv"))
    if ev_tables:
        ev = pl.concat(ev_tables, how="diagonal_relaxed")
        ev.write_csv(os.path.join(a.out, "deteccao_por_evento.csv"))
        grp = [c for c in ("atk_regime", "atk_origem") if c in ev.columns]
        if grp:
            reg = (ev.group_by(["detector"] + grp)
                     .agg([pl.col("modelo").mean().round(3).alias("recall_evento_modelo"),
                           pl.col("firewall").mean().round(3).alias("recall_evento_firewall"),
                           pl.len().alias("eventos")])
                     .sort(grp + ["detector"]))
            reg.write_csv(os.path.join(a.out, "deteccao_por_regime.csv"))
            print("\nDetecção por regime (tabela central do cap. 5):")
            print(reg)
    print("\nResumo:")
    with pl.Config(tbl_cols=12, tbl_width_chars=160):
        print(resumo)

    # 5. bundle para inferência ----------------------------------------------
    chk_idx = rng.choice(te.shape[0], min(2000, te.shape[0]), replace=False)
    chk_raw = X_te[chk_idx]
    check = {"X_raw": chk_raw,
             "scores": {n: d.score(scaler.transform(chk_raw).astype(np.float32))
                        for n, d in keep.items()}}
    bundle = {
        "detectors": keep, "scaler": scaler, "encoders": enc, "features": feats,
        "windows": cf.WINDOWS, "causal": True, "q": a.q, "min_votes": a.min_votes,
        "unit_map": cf.UNIT_MAP, "wan_ifaces": cf.WAN_IFACES,
        "check": check,
        "info": {"criado": time.strftime("%Y-%m-%d %H:%M:%S"), "total_linhas": total,
                 "dias": n_days, "n_treino": tr.shape[0],
                 "normal_por_dia": n_normal_day, "backends": M.backend_report(),
                 "python": platform.python_version(), "polars": pl.__version__},
    }
    path = os.path.join(a.out, "bundle.joblib")
    joblib.dump(bundle, path, compress=3)
    json.dump(bundle["info"], open(os.path.join(a.out, "info.json"), "w"), indent=2)
    print(f"\nBundle salvo em {path} ({os.path.getsize(path)/1e6:.1f} MB)")


if __name__ == "__main__":
    main()
