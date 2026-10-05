#!/usr/bin/env python3
"""
=============================================================================
injetor_sintetico.py — Injeção de ataques sintéticos em logs reais (T8)
=============================================================================
Mesma ideia do ID2T (Garcia Cordero et al., 2021), aplicada no nível do log
de firewall: eventos de ataque são gerados no formato exato das linhas do
roteador e inseridos no TRÁFEGO DE FUNDO REAL, imitando suas propriedades:

  * prefixo das linhas de log e cadeia (forward / input);
  * interfaces (bridge da origem, bridge ou WAN do destino);
  * MAC de origem observado em cada interface de entrada;
  * hosts reais de cada bridge como origem e alvo ("auto:<bridge>");
  * taxa de duplicação do syslog observada no próprio arquivo.

Cada evento é registrado no ataques.csv (origem = sintetico, regime =
abaixo, com dst_ip), para servir SÓ de conjunto de teste.

Tipos de cenário:
  portscan_lento     uma origem sonda portas de um alvo em ritmo lento
                     (SYN; resposta RST,ACK opcional quando cruza o roteador)
  bruteforce_lento   conexões TCP completas e espaçadas a uma porta de serviço
  scan_distribuido   várias origens repartem as portas de um mesmo alvo

Os arquivos originais não são alterados: a saída vai para --out, com os
mesmos nomes. Depois, rode export_to_parquet sobre a pasta de saída.

Uso:
  python injetor_sintetico.py --export "export/*.txt" --cenarios cenarios.json \\
         --out export_injetado --ataques ataques.csv [--limiar-portas 21 --limiar-janela-s 3]

O limiar (--limiar-portas / --limiar-janela-s) só VALIDA que nenhum cenário
ultrapassa a regra estática; não vai para o texto do TCC.
=============================================================================
"""
import argparse, csv, glob, gzip, json, os, random
import datetime as dt
import numpy as np
import polars as pl

import common_features_polars as cf

TZ = dt.timezone(dt.timedelta(hours=-3))
NS = 1_000_000_000


# --------------------------------------------------------------------------
# Perfil do tráfego de fundo
# --------------------------------------------------------------------------
class Perfil:
    def __init__(self, raw, host, dedup_tol_s=cf.DEDUP_TOL_S):
        self.host = host
        p = cf.parse_frame(raw, verbose=False)
        normal = p.filter(pl.col("fw_flag") == 0)
        self.day = p["dt"].min().date()
        # prefixo mais comum por cadeia (ex.: "access")
        self.prefix = {}
        for ch in ("forward", "input"):
            g = normal.filter(pl.col("chain") == ch)["prefix"]
            self.prefix[ch] = g.mode().item(0) if g.len() else None
        if self.prefix["input"] is None:
            self.prefix["input"] = self.prefix["forward"]
        # MAC mais comum por interface de entrada
        self.mac = dict(normal.group_by("iface_in")
                              .agg(pl.col("src_mac").drop_nulls().mode().first())
                              .iter_rows())
        # hosts internos por bridge (como origem) e alvos por interface de saída
        wan = set(cf.WAN_IFACES.get(host, []))
        self.wan = next(iter(wan), None) or (
            normal["iface_out"].mode().item(0))
        self.src_hosts = {b: sorted(g["src_ip"].unique().to_list())
                          for (b,), g in normal.filter(~pl.col("iface_in").is_in(list(wan)))
                                               .group_by(["iface_in"])}
        dst_int = (normal.filter(pl.col("dst_ip").str.contains(cf.RE_PRIVATE)
                                 & ~pl.col("iface_out").is_in(list(wan) + ["(unknown 0)"]))
                         .group_by(["iface_out", "dst_ip"]).len()
                         .sort("len", descending=True))
        dst_int = dst_int.sort(["len", "dst_ip"], descending=[True, False])
        self.dst_hosts = {b: g["dst_ip"].to_list()
                          for (b,), g in dst_int.group_by(["iface_out"], maintain_order=True)}
        self.iface_of_dst = dict(dst_int.sort("len", descending=True)
                                        .unique("dst_ip", keep="first")
                                        .select(["dst_ip", "iface_out"]).iter_rows())
        self.iface_of_src = dict(normal.group_by(["src_ip", "iface_in"]).len()
                                       .sort("len", descending=True)
                                       .unique("src_ip", keep="first")
                                       .select(["src_ip", "iface_in"]).iter_rows())
        # quantas linhas de cada cadeia o roteador registra de fato
        self.n_chain = dict(p.group_by("chain").len().iter_rows())
        # duplicação do syslog observada, com a MESMA tolerância do pipeline
        # (0 = sem duplicação sistemática, então nenhuma cópia é injetada)
        n0 = raw.height
        n1 = cf.dedup_frame(raw, "tolerance", dedup_tol_s).height if dedup_tol_s > 0 else n0
        self.dup_rate = (n0 - n1) / n0 if n0 else 0.0

    def resolve(self, spec, papel, rng):
        """'auto:<bridge>' -> (host real daquela bridge, bridge);
        IP literal -> (IP, None: a bridge vem do tráfego de fundo)."""
        if not str(spec).startswith("auto:"):
            return str(spec), None
        b = spec.split(":", 1)[1]
        pool = (self.src_hosts if papel == "origem" else self.dst_hosts).get(b, [])
        if not pool:
            raise SystemExit(f"[{self.host}] nenhum host observado em {b} para {papel}")
        return rng.choice(pool[:20] if papel == "alvo" else pool), b


# --------------------------------------------------------------------------
# Geração das linhas
# --------------------------------------------------------------------------
def linha(prefix, chain, i_in, i_out, mac, flags, src, sp, dst, dp, ln):
    pre = f"{prefix} " if prefix else ""
    macs = f"src-mac {mac}, " if mac else ""
    return (f"{pre}{chain}: in:{i_in} out:{i_out}, {macs}proto TCP ({flags}), "
            f"{src}:{sp}->{dst}:{dp}, len {ln}")


def rota(perfil, src, dst, chain, b_src=None, b_dst=None):
    i_in = b_src or perfil.iface_of_src.get(src)
    if i_in is None:
        raise SystemExit(f"[{perfil.host}] origem {src} não aparece no tráfego de fundo")
    if chain == "input":
        return i_in, "(unknown 0)"
    return i_in, b_dst or perfil.iface_of_dst.get(dst, perfil.wan)


def portas(spec, rng):
    if isinstance(spec, list):
        return list(spec)
    a, b = (int(x) for x in str(spec).split("-"))
    ps = list(range(a, b + 1))
    rng.shuffle(ps)
    return ps


def gen_portscan(perfil, src, dst, chain, ps, t0, t1, iv, rng, resp=0.5, bs=None, bd=None):
    i_in, i_out = rota(perfil, src, dst, chain, bs, bd)
    pre = perfil.prefix[chain]
    out, t = [], t0
    for dp in ps:
        if t > t1:
            break
        sp = rng.randint(32768, 60999)
        out.append((t, linha(pre, chain, i_in, i_out, perfil.mac.get(i_in), "SYN",
                             src, sp, dst, dp, 60)))
        if chain == "forward" and rng.random() < resp:      # porta fechada responde RST
            out.append((t + rng.randint(1, 30) * 1_000_000,
                        linha(pre, "forward", i_out, i_in, perfil.mac.get(i_out),
                              "RST,ACK", dst, dp, src, sp, 40)))
        t += int(rng.uniform(*iv) * NS)
    return out


def gen_bruteforce(perfil, src, dst, chain, dp, t0, t1, iv, rng, bs=None, bd=None):
    i_in, i_out = rota(perfil, src, dst, chain, bs, bd)
    pre = perfil.prefix[chain]
    m_in, m_out = perfil.mac.get(i_in), perfil.mac.get(i_out)
    out, t = [], t0
    while t <= t1:
        sp = rng.randint(32768, 60999)
        seq = [("c", "SYN", 60), ("s", "SYN,ACK", 60), ("c", "ACK", 52)]
        for _ in range(rng.randint(2, 4)):                    # troca de autenticação
            seq += [("c", "ACK,PSH", rng.randint(80, 220)), ("s", "ACK,PSH", rng.randint(60, 180))]
        seq += [("s", "FIN,ACK", 52), ("c", "FIN,ACK", 52), ("c", "ACK", 52)]
        tt = t
        for who, fl, ln in seq:
            if who == "c":
                out.append((tt, linha(pre, chain, i_in, i_out, m_in, fl, src, sp, dst, dp, ln)))
            elif chain == "forward":
                out.append((tt, linha(pre, "forward", i_out, i_in, m_out, fl, dst, dp, src, sp, ln)))
            tt += rng.randint(2, 40) * 1_000_000
        t += int(rng.uniform(*iv) * NS)
    return out


def dup(lines, rate, rng):
    extra = [(t + rng.randint(50, 5000) * 1000, l) for t, l in lines if rng.random() < rate]
    return lines + extra


def max_ports_window(lines, janela_s):
    """Maior nº de portas distintas sondadas por uma origem em qualquer janela."""
    if not lines:
        return 0
    df = pl.DataFrame({"ts": [t for t, _ in lines], "l": [l for _, l in lines]})
    df = df.filter(pl.col("l").str.contains(r"\(SYN\)")).with_columns(
        pl.col("l").str.extract(r"(\d+\.\d+\.\d+\.\d+):\d+->").alias("s"),
        pl.col("l").str.extract(r"->\d+\.\d+\.\d+\.\d+:(\d+)").alias("p")).sort("ts")
    best = 0
    for (_,), g in df.group_by(["s"]):
        ts, ps = g["ts"].to_list(), g["p"].to_list()
        j = 0
        for i in range(len(ts)):
            while ts[i] - ts[j] > janela_s * NS:
                j += 1
            best = max(best, len(set(ps[j:i + 1])))
    return best


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--export", required=True, help='glob dos exports originais')
    ap.add_argument("--cenarios", required=True, help="JSON com a lista de cenários")
    ap.add_argument("--out", default="export_injetado")
    ap.add_argument("--ataques", default="ataques.csv", help="CSV de ground truth (acrescenta linhas)")
    ap.add_argument("--semente", type=int, default=42)
    ap.add_argument("--dedup-tol", type=float, default=cf.DEDUP_TOL_S,
                    help="tolerância da dedup do pipeline (s); 0 = logs sem duplicação")
    ap.add_argument("--limiar-portas", type=int, help="validação: máx. portas por janela")
    ap.add_argument("--limiar-janela-s", type=float, default=3.0)
    a = ap.parse_args()

    rng = random.Random(a.semente)
    files = {os.path.basename(f): f for f in sorted(glob.glob(a.export))}
    cen = json.load(open(a.cenarios, encoding="utf-8"))
    os.makedirs(a.out, exist_ok=True)
    por_arquivo = {}
    for c in cen:
        if c["arquivo"] not in files:
            raise SystemExit(f"arquivo do cenário não encontrado: {c['arquivo']}")
        por_arquivo.setdefault(c["arquivo"], []).append(c)

    novos_eventos = []
    for nome, path in files.items():
        raw = cf.read_export(path)
        cens = por_arquivo.get(nome, [])
        if not cens:
            injected = []
        else:
            host = raw["hostname"].drop_nulls().mode().item(0)
            perfil = Perfil(raw, host, a.dedup_tol)
            print(f"[{nome}] fundo={raw.height:,} linhas | prefixo={perfil.prefix} | "
                  f"duplicação observada={100*perfil.dup_rate:.1f}%")
            injected = []
            for c in cens:
                chain = c.get("chain", "forward")
                if perfil.n_chain.get(chain, 0) < 100:
                    raise SystemExit(
                        f"[{nome}] cenário '{c['tipo']}' usa a cadeia '{chain}', mas o roteador "
                        f"registrou só {perfil.n_chain.get(chain, 0)} linha(s) dela no dia: as "
                        f"linhas injetadas seriam artificiais. Use chain='forward'.")
                ini = c.get("inicio", "auto")
                if ini == "auto":
                    h = rng.uniform(8, 17 - c["duracao_min"] / 60)
                    t0dt = dt.datetime.combine(perfil.day, dt.time(0), TZ) + dt.timedelta(hours=h)
                else:
                    hh, mm = (int(x) for x in ini.split(":"))
                    t0dt = dt.datetime.combine(perfil.day, dt.time(hh, mm), TZ)
                t0 = int(t0dt.timestamp() * NS)
                t1 = t0 + int(c["duracao_min"] * 60 * NS)
                iv = tuple(c["intervalo_s"])
                dst, bd = perfil.resolve(c["alvo"], "alvo", rng)
                if c["tipo"] == "portscan_lento":
                    src, bs = perfil.resolve(c["origem"], "origem", rng)
                    grupos = {src: gen_portscan(perfil, src, dst, chain,
                                                portas(c.get("portas", "1-1024"), rng),
                                                t0, t1, iv, rng, bs=bs, bd=bd)}
                elif c["tipo"] == "bruteforce_lento":
                    src, bs = perfil.resolve(c["origem"], "origem", rng)
                    grupos = {src: gen_bruteforce(perfil, src, dst, chain, int(c.get("porta", 22)),
                                                  t0, t1, iv, rng, bs=bs, bd=bd)}
                elif c["tipo"] == "scan_distribuido":
                    pool = {}
                    for _ in range(60):
                        ip, b = perfil.resolve(c["origens"], "origem", rng)
                        pool.setdefault(ip, b)
                    srcs = list(pool)[: c.get("n_origens", 5)]
                    ps = portas(c.get("portas", "1-512"), rng)
                    fatia = int(np.ceil(len(ps) / len(srcs)))
                    grupos = {s: gen_portscan(perfil, s, dst, chain, ps[k * fatia:(k + 1) * fatia],
                                              t0 + rng.randint(0, 600) * NS, t1, iv, rng,
                                              bs=pool[s], bd=bd)
                              for k, s in enumerate(srcs)}
                else:
                    raise SystemExit(f"tipo desconhecido: {c['tipo']}")
                for s, ls in grupos.items():
                    if not ls:
                        continue
                    if a.limiar_portas:
                        mx = max_ports_window(ls, a.limiar_janela_s)
                        if mx >= a.limiar_portas:
                            raise SystemExit(f"[{nome}] {c['tipo']} de {s} atinge {mx} portas em "
                                             f"{a.limiar_janela_s}s (limiar {a.limiar_portas}): "
                                             f"aumente intervalo_s")
                    ls = dup(ls, perfil.dup_rate, rng)
                    injected += [(t, host, l) for t, l in ls]
                    ts = [t for t, _ in ls]
                    fmt = lambda n: dt.datetime.fromtimestamp(n / NS, TZ).strftime("%Y-%m-%d %H:%M:%S")
                    novos_eventos.append({
                        "start": fmt(min(ts)), "end": fmt(max(ts) + NS), "src_ip": s,
                        "dst_ip": dst, "regime": "abaixo", "origem": "sintetico",
                        "tipo": c["tipo"], "gerador": "injetor"})
                    print(f"   + {c['tipo']:17s} {s} -> {dst} ({chain}) "
                          f"{novos_eventos[-1]['start']} a {novos_eventos[-1]['end'][11:]} "
                          f"| {len(ls):,} linhas")
        # grava arquivo (original + injetado), em ordem de tempo
        inj = pl.DataFrame({"ts": [t for t, _, _ in injected],
                            "hostname": [h for _, h, _ in injected],
                            "content": [l for _, _, l in injected]},
                           schema={"ts": pl.Int64, "hostname": pl.Utf8, "content": pl.Utf8})
        allr = pl.concat([raw, inj]).sort("ts", maintain_order=True)
        out = os.path.join(a.out, nome)
        opener = gzip.open if nome.endswith(".gz") else open
        with opener(out, "wt", encoding="utf-8") as fh:
            for t, h, l in allr.iter_rows():
                fh.write(f"{t}\t{h}\t{l}\n")
        # confere que todas as linhas injetadas passam no parser
        if inj.height:
            ok = cf.parse_frame(inj, verbose=False).height
            if ok != inj.height:
                raise SystemExit(f"[{nome}] {inj.height - ok} linhas injetadas não passaram no parser")

    # acrescenta os eventos ao ground truth (mantém as linhas existentes)
    cols = ["start", "end", "src_ip", "dst_ip", "regime", "origem", "tipo", "gerador"]
    old = []
    if os.path.exists(a.ataques):
        with open(a.ataques, newline="", encoding="utf-8") as fh:
            old = list(csv.DictReader(fh))
        # reexecução substitui SÓ o que o próprio injetor gerou
        old = [r for r in old if r.get("gerador") != "injetor"]
    with open(a.ataques, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in old + novos_eventos:
            w.writerow({k: r.get(k, "") for k in cols})
    print(f"\n{len(novos_eventos)} evento(s) sintético(s) injetado(s); "
          f"{a.ataques} com {len(old) + len(novos_eventos)} evento(s) no total; saída em {a.out}/")


if __name__ == "__main__":
    main()
