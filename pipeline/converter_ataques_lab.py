#!/usr/bin/env python3
"""
=============================================================================
converter_ataques_lab.py — ataques_horarios.txt -> ataques_lab.csv (T7)
=============================================================================
Lê o registro dos ataques de laboratório no formato
    <tipo> INÍCIO: [AAAA-MM-DD ]HH:MM:SS
    <tipo> FIM:    [AAAA-MM-DD ]HH:MM:SS
(linhas sem data herdam a última data vista; um INÍCIO sem FIM tem o fim
inferido pelos logs) e cruza cada evento com o export do dia:

  * alvo (dst_ip): o destino mais frequente das linhas da origem no evento;
  * fim inferido: última linha da origem antes do próximo evento + margem;
  * o que o evento deixou nos logs: linhas de detecção (_atk), quantas são
    únicas (duplicação das detecções) e linhas de tráfego forward da origem.

Uso:
  python converter_ataques_lab.py --horarios ~/ataques_horarios.txt \\
         --export export_lab/ROTEADOR_1_2026-09-16.txt.gz --origem 10.0.1.21 --out ataques_lab.csv
=============================================================================
"""
import argparse, csv, re
import datetime as dt
import polars as pl

import common_features_polars as cf

RE_LINHA = re.compile(r"^\s*(?P<tipo>[\w-]+)\s+(?P<ev>IN[IÍ]CIO|FIM)\s*:\s*"
                      r"(?:(?P<data>\d{4}-\d{2}-\d{2})\s+)?(?P<hora>\d{1,2}:\d{2}:\d{2})",
                      re.IGNORECASE)
TIPO = {"port-scan": "portscan", "brute-force": "bruteforce", "icmp": "icmp_flood"}


def tipo_base(t):
    t = t.lower()
    for k, v in TIPO.items():
        if t.startswith(k):
            return v
    return t


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--horarios", required=True)
    ap.add_argument("--export", required=True, help="export do dia dos ataques")
    ap.add_argument("--origem", required=True, help="IP da estação de ataque")
    ap.add_argument("--out", default="ataques_lab.csv")
    ap.add_argument("--out-carac", default="caracterizacao_firewall_lab.csv",
                    help="tabela SEM IPs para o cap. 5 (vai no pacote de resultados)")
    ap.add_argument("--roteador-ip", help="IP do roteador (para classificar o alvo)")
    ap.add_argument("--broadcast", help="endereço de broadcast da sub-rede")
    ap.add_argument("--margem-s", type=int, default=30)
    ap.add_argument("--max-inferido-min", type=int, default=15,
                    help="teto para o fim inferido de um evento sem FIM")
    a = ap.parse_args()

    # 1. eventos do arquivo de horários
    evs, data = [], None
    for ln in open(a.horarios, encoding="utf-8", errors="replace"):
        m = RE_LINHA.match(ln)
        if not m:
            continue
        data = m["data"] or data
        if data is None:
            raise SystemExit(f"linha sem data antes de qualquer data: {ln.strip()}")
        t = dt.datetime.fromisoformat(f"{data} {m['hora']}")
        if m["ev"].upper().startswith("IN"):
            evs.append({"nome": m["tipo"], "start": t, "end": None})
        else:
            aberto = [e for e in evs if e["nome"] == m["tipo"] and e["end"] is None]
            if aberto:
                aberto[-1]["end"] = t
    evs.sort(key=lambda e: e["start"])

    # 2. linhas da origem no dia
    df = cf.parse_frame(cf.read_export(a.export), verbose=False)
    src = df.filter(pl.col("src_ip") == a.origem)
    print(f"{a.export}: {df.height:,} linhas; {src.height:,} da origem {a.origem}")

    rows = []
    for i, e in enumerate(evs):
        prox = evs[i + 1]["start"] if i + 1 < len(evs) else e["start"] + dt.timedelta(hours=2)
        lim = e["end"] or min(prox, e["start"] + dt.timedelta(minutes=a.max_inferido_min))
        w = src.filter((pl.col("dt") >= e["start"]) & (pl.col("dt") <= lim + dt.timedelta(seconds=a.margem_s)))
        atk = w.filter(pl.col("fw_flag") == 1)
        base = atk if atk.height else w
        dst = base["dst_ip"].mode().item(0) if base.height else ""
        fim_inferido = e["end"] is None
        if fim_inferido:
            # fim = última evidência PARA O ALVO (o tráfego normal da estação não conta)
            last = w.filter(pl.col("dst_ip") == dst)["dt"].max() if dst else None
            e["end"] = (last if last is not None else e["start"]) + dt.timedelta(seconds=a.margem_s)
        else:
            e["end"] = e["end"] + dt.timedelta(seconds=a.margem_s)
        rows.append({
            "start": e["start"].strftime("%Y-%m-%d %H:%M:%S"),
            "end": e["end"].strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": a.origem, "dst_ip": dst, "regime": "acima", "origem": "real",
            "tipo": tipo_base(e["nome"]), "gerador": "laboratorio",
            "_nome": e["nome"], "_fim_inferido": fim_inferido,
            "_linhas_atk": atk.height,
            "_atk_unicas": atk.select(["ts", "src_port", "dst_port", "prefix"]).unique().height,
            "_portas_atk": ",".join(str(p) for p in sorted(set(atk["dst_port"].to_list()))[:8]),
            "_forward_da_origem": w.filter(pl.col("chain") == "forward").height,
            "_forward_destinos": w.filter(pl.col("chain") == "forward")["dst_ip"].n_unique(),
        })

    cols = ["start", "end", "src_ip", "dst_ip", "regime", "origem", "tipo", "gerador"]
    with open(a.out, "w", newline="", encoding="utf-8") as fh:
        wtr = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        wtr.writeheader()
        wtr.writerows(rows)
    def alvo_tipo(ip):
        if a.roteador_ip and ip == a.roteador_ip:
            return "roteador"
        if a.broadcast and ip == a.broadcast:
            return "broadcast da sub-rede"
        return "host interno" if ip else "indeterminado"
    carac = pl.DataFrame([{
        "evento": i + 1, "tipo": r["tipo"],
        "duracao_s": int((dt.datetime.fromisoformat(r["end"]) -
                          dt.datetime.fromisoformat(r["start"])).total_seconds()) - a.margem_s,
        "fim_inferido_pelos_logs": r["_fim_inferido"],
        "alvo": alvo_tipo(r["dst_ip"]),
        "linhas_deteccao": r["_linhas_atk"],
        "portas_distintas_registradas": len(r["_portas_atk"].split(",")) if r["_portas_atk"] else 0,
        "portas_exemplo": r["_portas_atk"],
        "trafego_forward_destinos": r["_forward_destinos"],
    } for i, r in enumerate(rows)])
    carac.write_csv(a.out_carac)
    print(f"\n{len(rows)} evento(s) em {a.out}; caracterização sem IPs em {a.out_carac}\n")
    with pl.Config(tbl_cols=20, tbl_width_chars=200, tbl_rows=30):
        print(pl.DataFrame(rows).select(["_nome", "start", "end", "_fim_inferido", "dst_ip",
                                         "_linhas_atk", "_atk_unicas", "_portas_atk",
                                         "_forward_da_origem", "_forward_destinos"]))


if __name__ == "__main__":
    main()
