#!/usr/bin/env python3
"""
=============================================================================
empacotar_saidas.py — Junta as saídas do pipeline num .zip seguro para envio
=============================================================================
O que entra (o que existir):
  modelos/*.csv, modelos/info.json         métricas do treino (NUNCA o bundle)
  relatorio_inferencia.json                testes T1–T6
  *_latencia_por_evento.csv, *_resumo.json replay do scanner
  analise/                                 análise por secretaria (CSV, JSON, PNG)
  a partir dos Parquet (--parquet):        estatística descritiva, período e
                                           volume por roteador e secretaria
  a partir dos exports brutos (--export):  histograma de duplicatas do syslog
  ambiente:                                versões das bibliotecas e imagens Docker
  respostas.md                             suas respostas às perguntas abertas

Segurança: TODO arquivo de texto é varrido; IPv4 vira [IP], MAC vira [MAC], e
nomes de secretarias e roteadores viram os rótulos anônimos, inclusive nos
nomes de arquivo. O LEIA-ME.md lista cada arquivo e cada substituição feita.
Imagens (PNG) não podem ser varridas: só entram as geradas pelos scripts do
pipeline, que já saem anonimizadas; confira-as mesmo assim.

Uso:
  python empacotar_saidas.py --parquet "pq/*.parquet" --export "export/*.txt.gz" \\
         [--modelos modelos --analise analise --replay "*_resumo.json" --out saidas_tcc.zip]
=============================================================================
"""
import argparse, glob, json, os, platform, re, shutil, subprocess, tempfile, zipfile
from datetime import datetime
import polars as pl

import common_features_polars as cf

RE_IP = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
RE_MAC = re.compile(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b")
TEXT_EXT = {".csv", ".json", ".md", ".txt", ".log"}

RESPOSTAS_MODELO = """# Respostas para o fechamento do TCC

Preencha e mantenha este arquivo junto das saídas. Não coloque IPs, MACs nem
nomes de secretarias (o empacotador troca, mas evite).

## Dados
- Período da coleta por roteador (se diferente do calculado):
- Tolerância de dedup escolhida (ms) e por quê (olhe dedup_histograma.csv):
- Contador RcvbufErrors do coletor (T4) — antes / depois da coleta:
- Resultado da consulta de visibilidade da cadeia input (T9):
- Algo anormal durante a coleta (quedas, reinícios, lacunas)?

## Ataques
- O que o generate.py fazia (tráfego executado ou linhas injetadas)?
- Quantos ataques reais foram executados e de que tipos?
- Quantos cenários foram injetados pelo injetor_sintetico.py?

## Decisões (orientador / coautor)
- T44 trilha supervisionada fora do escopo?
- T45 MLflow fora do texto ou em trabalhos futuros?
- T47 cidade na capa?
- T46 One-Class SVM: Nyström ou ThunderSVM?

## Execução
- GPU usada (cuML)? Quais algoritmos rodaram nela?
- Comandos exatos usados (train.py, test_inference.py, replay):
- Observações sobre os resultados (algo que pareceu estranho):
"""


def anon_text(s):
    pairs = sorted({**cf.HOST_ANON, **cf.UNIT_ANON}.items(), key=lambda kv: -len(kv[0]))
    n = 0
    for real, fake in pairs:
        k = s.count(real)
        if k:
            s = s.replace(real, fake)
            n += k
    return s, n


def sanitize_file(path):
    txt = open(path, encoding="utf-8", errors="replace").read()
    txt, n_ip = RE_IP.subn("[IP]", txt)
    txt, n_mac = RE_MAC.subn("[MAC]", txt)
    txt, n_nome = anon_text(txt)
    open(path, "w", encoding="utf-8").write(txt)
    return n_ip, n_mac, n_nome


def dedup_histograma(paths, max_lines):
    edges = [0, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 1_000_000_000, None]
    nomes = ["<10us", "10-100us", "0.1-1ms", "1-10ms", "10-100ms", "0.1-1s", ">=1s"]
    rows = []
    for p in paths:
        raw = cf.read_export(p, max_lines=max_lines)
        d = (raw.sort(["hostname", "content", "ts"])
                .with_columns(pl.col("ts").diff().over(["hostname", "content"]).alias("dt"))
                .filter(pl.col("dt").is_not_null()))
        for (lo, hi), nm in zip(zip(edges[:-1], edges[1:]), nomes):
            m = (pl.col("dt") >= lo) & ((pl.col("dt") < hi) if hi else pl.lit(True))
            rows.append({"arquivo": os.path.basename(p), "linhas_lidas": raw.height,
                         "faixa": nm, "repeticoes": d.filter(m).height})
        for tol in (0.0001, 0.001, 0.01):
            rows.append({"arquivo": os.path.basename(p), "linhas_lidas": raw.height,
                         "faixa": f"removidas_com_tol_{tol*1000:g}ms",
                         "repeticoes": raw.height - cf.dedup_frame(raw, "tolerance", tol).height})
    return pl.DataFrame(rows)


def ambiente():
    info = {"data": datetime.now().isoformat(timespec="seconds"),
            "python": platform.python_version(), "sistema": platform.platform()}
    for mod in ("polars", "numpy", "sklearn", "joblib", "cuml", "cupy", "thundersvm", "matplotlib"):
        try:
            m = __import__(mod)
            info[mod] = getattr(m, "__version__", "instalado")
        except Exception:
            info[mod] = None
    try:
        out = subprocess.run(["docker", "ps", "--format", "{{.Image}}"], capture_output=True,
                             text=True, timeout=10)
        info["docker_imagens"] = sorted(set(out.stdout.split())) if out.returncode == 0 else None
    except Exception:
        info["docker_imagens"] = None
    try:
        import models as M
        info["backends_modelos"] = M.backend_report()
    except Exception:
        pass
    return info


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--modelos", default="modelos")
    ap.add_argument("--relatorio", default="relatorio_inferencia.json")
    ap.add_argument("--replay", default="*_resumo.json",
                    help="glob dos resumos do replay (a latência é achada pelo mesmo prefixo)")
    ap.add_argument("--analise", default="analise")
    ap.add_argument("--parquet", help='glob dos Parquet, ex. "pq/*.parquet"')
    ap.add_argument("--export", help='glob dos exports brutos (histograma de dedup)')
    ap.add_argument("--max-linhas-dedup", type=int, default=2_000_000)
    ap.add_argument("--respostas", default="respostas.md")
    ap.add_argument("--out", default=f"saidas_tcc_{datetime.now():%Y%m%d_%H%M}.zip")
    a = ap.parse_args()

    stage = tempfile.mkdtemp(prefix="saidas_tcc_")
    inc, falt = [], []

    def put(src, dest_rel):
        dest = os.path.join(stage, dest_rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(src, dest)
        inc.append(dest_rel)

    # 1. treino
    if os.path.isdir(a.modelos):
        for f in sorted(glob.glob(os.path.join(a.modelos, "*.csv")) +
                        glob.glob(os.path.join(a.modelos, "info.json"))):
            put(f, f"treino/{os.path.basename(f)}")
    else:
        falt.append(f"treino ({a.modelos}/)")
    # 2. testes de inferência
    if os.path.exists(a.relatorio):
        put(a.relatorio, "inferencia/relatorio_inferencia.json")
    else:
        falt.append("relatorio_inferencia.json")
    # 3. replay
    res = sorted(glob.glob(a.replay))
    for f in res:
        put(f, f"replay/{os.path.basename(f)}")
        lat = f.replace("_resumo.json", "_latencia_por_evento.csv")
        if os.path.exists(lat):
            put(lat, f"replay/{os.path.basename(lat)}")
    if not res:
        falt.append("replay (*_resumo.json)")
    # 4. análise por secretaria
    if os.path.isdir(a.analise):
        for f in sorted(glob.glob(os.path.join(a.analise, "*"))):
            if os.path.splitext(f)[1] in {".csv", ".json", ".png"}:
                put(f, f"analise/{os.path.basename(f)}")
    else:
        falt.append(f"análise por secretaria ({a.analise}/)")
    # 4b. caracterização das regras estáticas (ataques de laboratório)
    for f in sorted(glob.glob("caracterizacao_firewall*.csv")):
        put(f, f"firewall/{os.path.basename(f)}")
    # 5. a partir dos Parquet
    if a.parquet and glob.glob(a.parquet):
        os.makedirs(os.path.join(stage, "dados"), exist_ok=True)
        print("Calculando estatística descritiva a partir dos Parquet...")
        for dim, t in cf.descriptive_stats(a.parquet).items():
            p = f"dados/estatistica_{dim}.csv"
            cf.anonymize(t).write_csv(os.path.join(stage, p))
            inc.append(p)
        lf = pl.scan_parquet(a.parquet)
        per = (lf.group_by(["hostname", "unidade"])
                 .agg([pl.len().alias("registros"), pl.col("dt").min().alias("inicio"),
                       pl.col("dt").max().alias("fim"),
                       pl.col("fw_flag").sum().alias("linhas_detectadas_pelo_firewall")])
                 .sort(["hostname", "unidade"]).collect())
        cf.anonymize(per).write_csv(os.path.join(stage, "dados/periodo_volume_por_unidade.csv"))
        inc.append("dados/periodo_volume_por_unidade.csv")
        if "is_atk" in lf.collect_schema().names():
            atk = (lf.filter(pl.col("is_atk") == 1)
                     .group_by([c for c in ("atk_evento", "atk_tipo", "atk_regime", "atk_origem")
                                if c in lf.collect_schema().names()])
                     .agg(pl.len().alias("registros"), pl.col("fw_flag").max().alias("firewall_detectou"))
                     .sort("atk_evento").collect())
            atk.write_csv(os.path.join(stage, "dados/eventos_rotulados.csv"))
            inc.append("dados/eventos_rotulados.csv")
    else:
        falt.append("estatística descritiva (--parquet)")
    # 6. histograma de duplicatas
    if a.export and glob.glob(a.export):
        print("Calculando o histograma de duplicatas (pode levar alguns minutos)...")
        h = dedup_histograma(sorted(glob.glob(a.export)), a.max_linhas_dedup)
        h.write_csv(os.path.join(stage, "dados/dedup_histograma.csv"))
        inc.append("dados/dedup_histograma.csv")
    else:
        falt.append("histograma de duplicatas (--export)")
    # 7. ambiente
    json.dump(ambiente(), open(os.path.join(stage, "ambiente.json"), "w"), indent=2,
              ensure_ascii=False, default=str)
    inc.append("ambiente.json")
    # 8. respostas
    if not os.path.exists(a.respostas):
        open(a.respostas, "w", encoding="utf-8").write(RESPOSTAS_MODELO)
        print(f"Criei {a.respostas} (modelo). Preencha e rode de novo.")
        falt.append("respostas.md preenchido")
    put(a.respostas, "respostas.md")

    # 9. sanitização de TODO arquivo de texto (conteúdo e nome)
    rel_san = []
    for rel in list(inc):
        path = os.path.join(stage, rel)
        novo_rel, n_nome_arq = anon_text(rel)
        if novo_rel != rel:
            os.makedirs(os.path.dirname(os.path.join(stage, novo_rel)), exist_ok=True)
            os.replace(path, os.path.join(stage, novo_rel))
            path = os.path.join(stage, novo_rel)
            inc[inc.index(rel)] = novo_rel
            rel = novo_rel
        if os.path.splitext(path)[1] in TEXT_EXT:
            n_ip, n_mac, n_nome = sanitize_file(path)
            rel_san.append((rel, n_ip, n_mac, n_nome + n_nome_arq))
        else:
            rel_san.append((rel, None, None, n_nome_arq))

    # 10. LEIA-ME
    lines = ["# Saídas do pipeline do TCC", "",
             f"Gerado em {datetime.now():%d/%m/%Y %H:%M}. Dados brutos, Parquet e o modelo "
             "(bundle.joblib) NÃO estão incluídos.", "",
             "## Sanitização", "",
             "| Arquivo | IPs trocados | MACs trocados | Nomes anonimizados |", "|---|---|---|---|"]
    for rel, a1, a2, a3 in sorted(rel_san):
        lines.append(f"| {rel} | {'—' if a1 is None else a1} | {'—' if a2 is None else a2} | {a3} |")
    lines += ["", "PNGs (—) não são varridos automaticamente: **abra e confira cada um antes de enviar.**"]
    if falt:
        lines += ["", "## Faltando nesta rodada", ""] + [f"- {x}" for x in falt]
    open(os.path.join(stage, "LEIA-ME.md"), "w", encoding="utf-8").write("\n".join(lines) + "\n")

    with zipfile.ZipFile(a.out, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(stage):
            for f in files:
                full = os.path.join(root, f)
                z.write(full, os.path.relpath(full, stage))
    shutil.rmtree(stage)
    mb = os.path.getsize(a.out) / 1e6
    print(f"\n{a.out}: {len(inc) + 1} arquivos, {mb:.2f} MB")
    tot_ip = sum(x[1] or 0 for x in rel_san)
    tot_mac = sum(x[2] or 0 for x in rel_san)
    print(f"Sanitização: {tot_ip} IPs e {tot_mac} MACs trocados (detalhes no LEIA-ME.md)")
    if falt:
        print("Faltando: " + "; ".join(falt))
    if mb > 25:
        print("ATENÇÃO: arquivo grande para upload; remova PNGs ou reduza o histograma.")


if __name__ == "__main__":
    main()
