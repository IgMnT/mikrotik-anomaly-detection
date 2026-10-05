#!/usr/bin/env python3
"""
=============================================================================
exportar_loki.py — Export do Loki: 1 arquivo por roteador por dia (T2/T3)
=============================================================================
  * Um arquivo por roteador e por dia: HOSTNAME_AAAA-MM-DD.txt.gz, com linhas
    <timestamp_ns>\\t<hostname>\\t<linha do log>
  * Dias cortados à MEIA-NOITE LOCAL (UTC-3), alinhados à janela de 24 h.
  * Download em paralelo por fatias de tempo (padrão 10 min), paginação sem
    perdas nem duplicatas, repetição automática em caso de erro de rede.
  * Ignora o proxy do ambiente (http_proxy), como no Promtail.
  * --verificar: compara o total exportado com count_over_time do próprio Loki.

Uso:
  python exportar_loki.py --de 2026-09-22 --ate 2026-09-22 --verificar      # um dia
  python exportar_loki.py --de 2026-09-18 --ate 2026-09-24 --verificar      # a semana
Opções: --hosts ROTEADOR_1,ROTEADOR_2 (padrão: descobre no Loki) --workers 4
=============================================================================
"""
import argparse, gzip, os, shutil, tempfile, time
import datetime as dt
from concurrent.futures import ThreadPoolExecutor

import requests

TZ = dt.timezone(dt.timedelta(hours=-3))
NS = 1_000_000_000


class Loki:
    def __init__(self, url, timeout=120):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.s = requests.Session()
        self.s.trust_env = False                 # ignora o proxy corporativo

    def get(self, path, params, tries=4):
        for k in range(tries):
            try:
                r = self.s.get(self.url + path, params=params, timeout=self.timeout)
                r.raise_for_status()
                return r.json()
            except Exception as e:
                if k == tries - 1:
                    raise
                time.sleep(2 ** k)
                print(f"      repetindo após erro: {e}")

    def hosts(self, job, start, end, label):
        j = self.get(f"/loki/api/v1/label/{label}/values",
                     {"start": str(start), "end": str(end),
                      "query": f'{{job="{job}"}}'})
        return sorted(j.get("data", []))

    def count(self, query_sel, start, end):
        secs = (end - start) // NS
        j = self.get("/loki/api/v1/query",
                     {"query": f"sum(count_over_time({query_sel}[{secs}s]))",
                      "time": str(end)})
        res = j["data"]["result"]
        return int(float(res[0]["value"][1])) if res else 0


def fetch_slice(loki, sel, host_label, cs, ce, limit, tmpdir):
    """Baixa [cs, ce) com paginação para frente. Grava num arquivo temporário."""
    path = os.path.join(tmpdir, f"{cs}.txt")
    n = 0
    cursor, seen = cs, set()
    with open(path, "w", encoding="utf-8") as fh:
        while cursor < ce:
            j = loki.get("/loki/api/v1/query_range",
                         {"query": sel, "start": str(cursor), "end": str(ce),
                          "limit": limit, "direction": "forward"})
            ent = []
            for st in j["data"]["result"]:
                h = st["stream"].get(host_label, "")
                ent += [(int(t), h, l) for t, l in st["values"]]
            if not ent:
                break
            ent.sort(key=lambda x: x[0])
            full = len(ent) >= limit
            new = [e for e in ent if not (e[0] == cursor and (e[0], e[1], e[2]) in seen)]
            for t, h, l in new:
                fh.write(f"{t}\t{h}\t{l.replace(chr(10), ' ')}\n")
            n += len(new)
            if not full:
                break
            last = ent[-1][0]
            at_last = {(t, h, l) for t, h, l in ent if t == last}
            if last == cursor:
                if not new:                     # página inteira no mesmo ns, já vista
                    cursor, seen = last + 1, set()
                    continue
                seen |= at_last
            else:
                seen = at_last
            cursor = last
    return cs, path, n


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--loki", default="http://localhost:3100")
    ap.add_argument("--job", default="mikrotik-firewall")
    ap.add_argument("--host-label", default="hostname")
    ap.add_argument("--hosts", help="lista separada por vírgula (padrão: descobre no Loki)")
    ap.add_argument("--de", required=True, help="primeiro dia, AAAA-MM-DD (horário local)")
    ap.add_argument("--ate", required=True, help="último dia, inclusive")
    ap.add_argument("--out", default="export")
    ap.add_argument("--limite", type=int, default=5000, help="linhas por página (limite do Loki)")
    ap.add_argument("--fatia-min", type=int, default=10)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--verificar", action="store_true")
    a = ap.parse_args()

    loki = Loki(a.loki)
    d0 = dt.date.fromisoformat(a.de)
    d1 = dt.date.fromisoformat(a.ate)
    dias = [d0 + dt.timedelta(days=k) for k in range((d1 - d0).days + 1)]
    ini = lambda d: int(dt.datetime.combine(d, dt.time(0), TZ).timestamp()) * NS
    hosts = (a.hosts.split(",") if a.hosts else
             loki.hosts(a.job, ini(d0), ini(d1 + dt.timedelta(days=1)), a.host_label))
    if not hosts:
        raise SystemExit("nenhum hostname encontrado; use --hosts")
    agora = time.time_ns()
    os.makedirs(a.out, exist_ok=True)
    print(f"Roteadores: {hosts} | dias: {[str(d) for d in dias]}")
    resumo = []
    for h in hosts:
        sel = f'{{job="{a.job}", {a.host_label}="{h}"}}'
        for d in dias:
            s, e = ini(d), ini(d + dt.timedelta(days=1))
            if e > agora:
                print(f"  ! {h} {d}: o dia ainda não terminou; arquivo ficará PARCIAL")
            step = a.fatia_min * 60 * NS
            fatias = [(c, min(c + step, e)) for c in range(s, e, step)]
            t0 = time.time()
            tmp = tempfile.mkdtemp(prefix="exp_")
            with ThreadPoolExecutor(a.workers) as ex:
                parts = list(ex.map(lambda f: fetch_slice(loki, sel, a.host_label, f[0], f[1],
                                                          a.limite, tmp), fatias))
            out = os.path.join(a.out, f"{h}_{d}.txt.gz")
            total = 0
            with gzip.open(out, "wt", encoding="utf-8", compresslevel=6) as gz:
                for cs, path, n in sorted(parts):
                    with open(path, encoding="utf-8") as fh:
                        shutil.copyfileobj(fh, gz)
                    total += n
            shutil.rmtree(tmp)
            linha = {"roteador": h, "dia": str(d), "linhas": total,
                     "mb": round(os.path.getsize(out) / 1e6, 1),
                     "min": round((time.time() - t0) / 60, 1)}
            if a.verificar:
                ref = loki.count(sel, s, min(e, agora))
                linha["loki"] = ref
                linha["dif"] = total - ref
            resumo.append(linha)
            print(f"  {h} {d}: {total:,} linhas, {linha['mb']} MB, {linha['min']} min"
                  + (f" | Loki: {linha['loki']:,} (dif {linha['dif']:+,})" if a.verificar else ""))
    if a.verificar:
        ruins = [r for r in resumo if r["dif"] != 0]
        print("\nConferência: " + ("todas as contagens batem com o Loki" if not ruins else
              f"{len(ruins)} arquivo(s) com diferença; reexporte-os"))


if __name__ == "__main__":
    main()
