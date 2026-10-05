#!/usr/bin/env python3
"""
=============================================================================
gerar_cenarios.py — Monta o cenarios.json a partir dos exports reais (T52)
=============================================================================
Lê os arquivos exportados, descobre em cada roteador e dia as bridges de cada
secretaria que têm hosts de origem e de destino, e distribui 5 cenários por
secretaria (15 no total), todos na cadeia forward:

  portscan_lento  ritmo A (15–45 s)     dia útil, expediente     movimento lateral
  portscan_lento  ritmo C (180–300 s)   dia útil, NOITE          movimento lateral
  bruteforce_lento ritmo B (60–120 s)   dia útil, expediente     lateral (SSH/RDP)
  scan_distribuido ritmo B/C            FIM DE SEMANA            várias origens
  portscan_lento  ritmo B (60–120 s)    dia útil, expediente     host interno -> internet

A variação de ritmo permite medir até que lentidão o modelo ainda detecta. O
alvo externo usa a faixa de documentação 203.0.113.0/24 (RFC 5737), que não
pertence a ninguém. Todos os cenários terminam antes da meia-noite do seu dia.

Uso:
  python gerar_cenarios.py --export "export/*.txt.gz" --out cenarios.json
  python gerar_cenarios.py --export "export/*_2026-09-22*" --dia-unico 2026-09-22 \\
         --out cenarios_22.json            # todos no mesmo dia (ensaio)
=============================================================================
"""
import argparse, glob, json, os, random, re
import polars as pl

import common_features_polars as cf

RITMO = {"A": [15, 45], "B": [60, 120], "C": [180, 300]}
DURACAO = {"A": 120, "B": 180, "C": 240}
RE_NOME = re.compile(r"^(?P<host>.+?)_(?P<dia>\d{4}-\d{2}-\d{2})")


def perfil_bridges(path, amostra=1_000_000, seed=0):
    """Bridges internas com hosts de origem e com hosts de destino internos."""
    raw = cf.read_export(path)
    if raw.height > amostra:
        raw = raw.sample(amostra, seed=seed)
    p = cf.add_unit_columns(cf.parse_frame(raw, verbose=False))
    host = p["hostname"].drop_nulls().mode().item(0)
    wan = set(cf.WAN_IFACES.get(host, []))
    origem = (p.filter(~pl.col("iface_in").is_in(list(wan)) & (pl.col("chain") == "forward"))
               .group_by(["iface_in", "unidade"]).agg(pl.col("src_ip").n_unique().alias("n")))
    destino = (p.filter(~pl.col("iface_out").is_in(list(wan) + ["(unknown 0)"])
                        & pl.col("dst_ip").str.contains(cf.RE_PRIVATE))
                .group_by("iface_out").agg(pl.col("dst_ip").n_unique().alias("n")))
    return {
        "host": host,
        "origem": {(b, u): n for b, u, n in origem.iter_rows()},
        "destino": {b: n for b, n in destino.iter_rows()},
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--export", required=True)
    ap.add_argument("--out", default="cenarios.json")
    ap.add_argument("--dia-unico", help="coloca todos os cenários neste dia (ensaio)")
    ap.add_argument("--semente", type=int, default=11)
    a = ap.parse_args()
    rng = random.Random(a.semente)

    arquivos = {}
    for f in sorted(glob.glob(a.export)):
        m = RE_NOME.match(os.path.basename(f))
        if m:
            arquivos[(m["host"], m["dia"])] = f
    if not arquivos:
        raise SystemExit(f"nenhum arquivo em {a.export}")
    print(f"Lendo {len(arquivos)} arquivo(s) para descobrir as bridges...")
    perf = {k: perfil_bridges(f) for k, f in arquivos.items()}

    fora = cf.UNIT_FORA_COMPARACAO
    secretarias = sorted({u for p in perf.values() for (b, u) in p["origem"]
                          if u not in fora and not u.endswith("(roteador)")})
    dias = sorted({d for (_, d) in arquivos})
    import datetime as dt
    fds = [d for d in dias if dt.date.fromisoformat(d).weekday() >= 5]
    uteis = [d for d in dias if d not in fds]
    if a.dia_unico:
        uteis, fds = [a.dia_unico], [a.dia_unico]
    if not uteis:
        raise SystemExit("nenhum dia útil entre os arquivos")
    fds = fds or uteis
    print(f"Secretarias: {secretarias} | dias úteis: {uteis} | fim de semana: {fds}")

    def opcoes(sec, dia):
        """(arquivo, bridges de origem da secretaria, bridges de destino) no dia."""
        for (h, d), p in perf.items():
            if d != dia:
                continue
            ori = [b for (b, u), n in p["origem"].items() if u == sec and n >= 2]
            if ori:
                dst = [b for b, n in p["destino"].items() if n >= 1]
                return os.path.basename(arquivos[(h, d)]), ori, dst
        return None

    def hora(ritmo, noite):
        dur = DURACAO[ritmo]
        if noite:
            ini = rng.choice(["20:30", "21:00", "01:00", "02:30"])
        else:
            fim_max = 17 * 60 - dur
            m = rng.randint(8 * 60 + 30, max(8 * 60 + 30, fim_max))
            ini = f"{m // 60:02d}:{m % 60:02d}"
        h, mi = (int(x) for x in ini.split(":"))
        if h * 60 + mi + dur >= 23 * 60 + 55:
            ini = "20:00"
        return ini, dur

    plano = [("portscan_lento", "A", "util", False, "lateral"),
             ("portscan_lento", "C", "util", True, "lateral"),
             ("bruteforce_lento", "B", "util", False, "lateral"),
             ("scan_distribuido", "C", "fds", False, "lateral"),
             ("portscan_lento", "B", "util", False, "externo")]
    cen, k_util, k_fds = [], 0, 0
    for sec in secretarias:
        for tipo, ritmo, quando, noite, alvo_tipo in plano:
            pool = uteis if quando == "util" else fds
            tent = pool[(k_util if quando == "util" else k_fds) % len(pool):] + pool
            if quando == "util":
                k_util += 1
            else:
                k_fds += 1
            esc = next(((d, o) for d in tent if (o := opcoes(sec, d))), None)
            if esc is None:
                print(f"  ! {sec} {tipo}: sem dados de origem nos dias disponíveis; pulado")
                continue
            dia, (arq, ori, dst) = esc
            b_ori = rng.choice(ori)
            c = {"arquivo": arq, "tipo": tipo, "chain": "forward",
                 "inicio": None, "duracao_min": None, "intervalo_s": RITMO[ritmo]}
            if alvo_tipo == "externo" or not [b for b in dst if b != b_ori]:
                if alvo_tipo == "lateral":
                    print(f"  ! {sec} {tipo} em {dia}: sem destino interno em outra bridge; "
                          f"usando alvo externo")
                alvo = f"203.0.113.{rng.randint(10, 250)}"
            else:
                alvo = "auto:" + rng.choice([b for b in dst if b != b_ori])
            c["inicio"], c["duracao_min"] = hora(ritmo, noite)
            if tipo == "scan_distribuido":
                c.update({"origens": f"auto:{b_ori}", "n_origens": 5, "alvo": alvo,
                          "portas": "1-512"})
            elif tipo == "bruteforce_lento":
                c.update({"origem": f"auto:{b_ori}", "alvo": alvo,
                          "porta": rng.choice([22, 3389])})
            else:
                c.update({"origem": f"auto:{b_ori}", "alvo": alvo, "portas": "1-1024"})
            c["_secretaria"] = sec
            c["_ritmo"] = ritmo
            cen.append(c)

    json.dump(cen, open(a.out, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"\n{len(cen)} cenário(s) em {a.out}:")
    tab = pl.DataFrame([{k: v for k, v in c.items() if k in
                         ("_secretaria", "tipo", "_ritmo", "arquivo", "inicio", "duracao_min")}
                        | {"alvo": c["alvo"]} for c in cen])
    with pl.Config(tbl_rows=40, tbl_width_chars=160):
        print(tab)


if __name__ == "__main__":
    main()
