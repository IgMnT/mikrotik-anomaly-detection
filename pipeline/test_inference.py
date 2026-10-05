#!/usr/bin/env python3
"""
=============================================================================
test_inference.py — Testes do modelo em modo de inferência (item 5.5 do TCC)
=============================================================================
Testes (cada um com APROVADO / REPROVADO / AVISO):

  T1 Integridade do bundle   recarrega os detectores e confere se reproduzem
                             os escores gravados no treino (conjunto de
                             verificação de 2.000 registros).
  T2 Consistência treino x   features de janela calculadas offline (como no
     serviço                 treino) x incrementalmente em lotes (como no
                             scanner): devem ser idênticas.
  T3 Dedup entre lotes       processar o arquivo em lotes deve remover as
                             mesmas duplicatas que o processamento de uma vez.
  T4 LOF manual x sklearn    a fórmula usada no caminho GPU confere com a
                             implementação de referência do scikit-learn.
  T5 Vocabulário             fração de valores categóricos (bridges,
                             protocolos) não vistos no treino (informativo).
  T6 Latência e capacidade   tempo por etapa e por tamanho de lote; compara a
                             vazão com a taxa de chegada de logs observada.

Uso:
  python test_inference.py --bundle modelos/bundle.joblib \\
         --export export/ROTEADOR_1_2026-09-17.txt [--lote-s 15] [--out relatorio.json]
=============================================================================
"""
import argparse, json, time
import numpy as np
import polars as pl

import common_features_polars as cf
import models as M
from inference import InferenceEngine

OK, FAIL, WARN = "APROVADO", "REPROVADO", "AVISO"


def batches_by_time(raw, step_s):
    raw = raw.sort("ts", maintain_order=True)
    t0, t1, step = raw["ts"].min(), raw["ts"].max(), int(step_s * 1e9)
    cur = t0
    while cur <= t1:
        b = raw.filter((pl.col("ts") >= cur) & (pl.col("ts") < cur + step))
        if b.height:
            yield b
        cur += step


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bundle", required=True)
    p.add_argument("--export", required=True, help="arquivo de export (texto) de 1 dia/roteador")
    p.add_argument("--lote-s", type=float, default=15, help="tamanho do lote (segundos de log)")
    p.add_argument("--dedup", default="tolerance", choices=["exact", "tolerance", "none"])
    p.add_argument("--dedup-tol", type=float, default=cf.DEDUP_TOL_S,
                   help="tolerância da dedup em segundos (ver diagnose_duplicates)")
    p.add_argument("--max-lotes", type=int, default=400,
                   help="limite de lotes nos testes T2/T3 (tempo de execução)")
    p.add_argument("--out", default="relatorio_inferencia.json")
    a = p.parse_args()
    dedup = None if a.dedup == "none" else a.dedup
    rep = {}

    def res(name, status, **info):
        rep[name] = {"status": status, **info}
        extra = " | ".join(f"{k}={v}" for k, v in info.items() if not isinstance(v, (dict, list)))
        print(f"[{status:9s}] {name}: {extra}")

    print("Backends:", M.backend_report())
    eng = InferenceEngine(a.bundle, dedup=dedup, dedup_tol_s=a.dedup_tol)
    b = eng.b
    print(f"Bundle: {len(eng.dets)} detectores, {len(b['features'])} features, "
          f"criado em {b['info']['criado']}\n")

    # ---------------------------------------------------------------- T1
    Xs = b["scaler"].transform(b["check"]["X_raw"]).astype(np.float32)
    diffs = {n: float(np.max(np.abs(d.score(Xs) - b["check"]["scores"][n])))
             for n, d in eng.dets.items()}
    worst = max(diffs.values())
    res("T1_integridade_bundle", OK if worst < 1e-4 else FAIL,
        dif_max=f"{worst:.2e}", por_modelo=diffs)

    # dados
    raw = cf.read_export(a.export).sort("ts")
    # T2, T3 e T6 usam a HORA DE PICO do arquivo (pior caso de carga),
    # limitada a max_lotes lotes
    H = 3_600_000_000_000
    per_h = raw.with_columns((pl.col("ts") // H).alias("h")).group_by("h").len()
    peak_h = per_h.sort("len", descending=True)["h"][0]
    t0 = peak_h * H
    t_end = min(t0 + H, t0 + int(a.max_lotes * a.lote_s * 1e9))
    raw_lim = raw.filter((pl.col("ts") >= t0) & (pl.col("ts") < t_end))
    print(f"Trecho de teste: hora de pico, {raw_lim.height:,} linhas brutas\n")

    # ---------------------------------------------------------------- T2
    raw_dd = cf.dedup_frame(raw_lim, dedup, a.dedup_tol).with_row_index("_rid")
    offline = cf.add_window_features(cf.parse_frame(raw_dd, verbose=False),
                                     b["windows"], causal=True)
    st = cf.WindowState(b["windows"])
    online = pl.concat([st.update(cf.parse_frame(x, verbose=False))
                        for x in batches_by_time(raw_dd, a.lote_s)])
    cols = cf.window_feature_names(b["windows"])
    A = offline.sort("_rid").select(cols).to_numpy()
    B = online.sort("_rid").select(cols).to_numpy()
    same = A.shape == B.shape
    dmax = float(np.max(np.abs(A - B))) if same else float("nan")
    res("T2_consistencia_treino_servico", OK if same and dmax < 1e-9 else FAIL,
        registros=offline.height, lotes=sum(1 for _ in batches_by_time(raw_dd, a.lote_s)),
        dif_max=f"{dmax:.2e}")

    # ---------------------------------------------------------------- T3
    n_once = cf.dedup_frame(raw_lim, dedup, a.dedup_tol).height
    e3 = InferenceEngine(b, dedup=dedup, dedup_tol_s=a.dedup_tol, models=[])
    n_stream = 0
    for x in batches_by_time(raw_lim, a.lote_s):
        n_stream += e3._dedup(x).height
    res("T3_dedup_entre_lotes", OK if n_once == n_stream else FAIL,
        de_uma_vez=n_once, em_lotes=n_stream, entrada=raw_lim.height)

    # ---------------------------------------------------------------- T4
    Xall = offline.head(40_000)
    Xf, _, _ = cf.build_features(Xall, encoders=b["encoders"], verbose=False)
    corr, rel = M.validate_lof(b["scaler"].transform(Xf), n=min(20_000, Xf.shape[0]))
    res("T4_lof_manual_vs_sklearn", OK if corr > 0.999 else FAIL,
        correlacao=f"{corr:.6f}", erro_rel_max=f"{rel:.2e}")

    # ---------------------------------------------------------------- T5
    unk = eng.unknown_categories(cf.add_unit_columns(offline))
    worst_unk = max((v["fracao"] for v in unk.values()), default=0.0)
    res("T5_vocabulario", OK if worst_unk == 0 else WARN,
        pior_fracao_desconhecida=f"{worst_unk:.4f}", detalhes=unk)
    for c, v in unk.items():
        if v["fracao"] > 0:
            print(f"        {c}: {100*v['fracao']:.1f}% fora do vocabulário, ex.: {v['exemplos']}")
    if worst_unk > 0:
        print("        valores novos recebem código -1 (já é um sinal de anomalia); se forem"
              " tráfego NORMAL novo\n        (bridge nova, secretaria nova), retreine ou"
              " atualize UNIT_MAP antes de usar em produção")

    # ---------------------------------------------------------------- T6
    eng6 = InferenceEngine(b, dedup=dedup, dedup_tol_s=a.dedup_tol)
    times, sizes = [], []
    for x in batches_by_time(raw_lim, a.lote_s):
        t = time.perf_counter()
        out = eng6.process(x)
        dt_total = time.perf_counter() - t
        if out is not None:
            times.append({**eng6.last_timings, "total": dt_total})
            sizes.append(out.height)
    if times:
        stages = {k: 1000 * float(np.mean([t.get(k, 0) for t in times])) for k in times[0]}
        rows_s = sum(sizes) / sum(t["total"] for t in times)
        p95 = 1000 * float(np.percentile([t["total"] for t in times], 95))
        ocup = stages["total"] / (1000 * a.lote_s)   # fração do intervalo gasta processando
        res("T6_latencia_capacidade",
            OK if ocup <= 0.33 else (WARN if ocup <= 1 else FAIL),
            lote_s=a.lote_s, registros_por_lote=round(float(np.mean(sizes)), 1),
            ms_por_lote=round(stages["total"], 1), p95_ms=round(p95, 1),
            vazao_reg_s=round(rows_s), ocupacao=f"{100*ocup:.1f}%",
            folga=f"{1/ocup:.0f}x" if ocup else "inf",
            etapas_ms={k: round(v, 2) for k, v in stages.items()})
        print("        tempo médio por etapa (ms/lote):",
              ", ".join(f"{k}={v:.1f}" for k, v in stages.items()))
        print("        ocupação = tempo de processamento / intervalo entre lotes; "
              "abaixo de 100% o scanner acompanha o fluxo")

    json.dump(rep, open(a.out, "w"), indent=2, ensure_ascii=False, default=str)
    falhas = [k for k, v in rep.items() if v["status"] == FAIL]
    print(f"\nRelatório: {a.out} | {'TODOS APROVADOS' if not falhas else 'FALHAS: ' + ', '.join(falhas)}")
    raise SystemExit(1 if falhas else 0)


if __name__ == "__main__":
    main()
