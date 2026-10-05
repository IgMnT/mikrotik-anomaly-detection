#!/usr/bin/env python3
"""
=============================================================================
realtime_scanner.py — Varredura em tempo quase real e alertas (solução primária)
=============================================================================
Ciclo (a cada --intervalo segundos):
  1. FONTE     busca na API do Loki as linhas novas desde o último cursor
               (paginado, 5000 por página), com hostname dos labels do stream.
               Modo --replay: reproduz um export gravado, com relógio virtual
               acelerado (demonstração e medição da latência de detecção).
  2. MOTOR     InferenceEngine: dedup (inclusive entre lotes), parse, unidade,
               janelas causais incrementais, 5 detectores, ensemble (>= N votos).
  3. ALERTAS   agrega os registros anômalos por (roteador, unidade, origem,
               janela de 5 min) em um único alerta, com severidade pelos votos
               e marcação "só ML" quando o firewall não sinalizou nada.
  4. SAÍDAS    console, arquivo JSONL e (opcional) push para o próprio Loki em
               {job="ml-anomaly"}, para visualização e alertas no Grafana.
               Labels de baixa cardinalidade (IP/porta vão no texto, nunca em
               label, para não repetir o erro 429 de streams).

Uso:
  # tempo real, Loki local
  python realtime_scanner.py --bundle modelos/bundle.joblib \\
         --loki http://localhost:3100 --push-loki

  # demonstração com dados gravados (60x mais rápido), medindo latência
  python realtime_scanner.py --bundle modelos/bundle.joblib \\
         --replay "export/*_2026-09-18.txt" --velocidade 60 --ataques ataques.csv

Observações:
  * Proxy: a sessão HTTP ignora http_proxy/https_proxy do ambiente
    (trust_env=False), o mesmo problema já resolvido no Promtail.
  * Aquecimento (--aquecimento): as features de janela de 1 h e 24 h dependem
    do histórico. "hora" reprocessa desde o início da hora corrente; "dia",
    desde a meia-noite (mais lento na partida, porém exato); "nenhum" parte do
    zero e subestima as janelas longas até elas virarem.
=============================================================================
"""
import argparse, glob, json, os, signal, sys, time
import datetime as dt
import numpy as np
import polars as pl

import common_features_polars as cf
from inference import InferenceEngine

TZ = dt.timezone(dt.timedelta(hours=-3))
NS = 1_000_000_000


# =============================================================================
# FONTES
# =============================================================================
class LokiSource:
    def __init__(self, url, query, host_label="hostname", lag_s=5, limit=5000,
                 start_ns=None, timeout=30):
        import requests
        self.s = requests.Session()
        self.s.trust_env = False                    # ignora o proxy corporativo
        self.url = url.rstrip("/")
        self.query, self.host_label = query, host_label
        self.lag, self.limit, self.timeout = lag_s, limit, timeout
        self.cursor = int(start_ns) if start_ns is not None else time.time_ns() - int(lag_s * NS)
        self._seen_at_cursor = set()

    def _page(self, start, end):
        r = self.s.get(f"{self.url}/loki/api/v1/query_range", timeout=self.timeout,
                       params={"query": self.query, "start": str(start), "end": str(end),
                               "limit": self.limit, "direction": "forward"})
        r.raise_for_status()
        ts, hosts, lines = [], [], []
        for stream in r.json()["data"]["result"]:
            h = stream["stream"].get(self.host_label)
            for t, line in stream["values"]:
                ts.append(int(t)); hosts.append(h); lines.append(line)
        return pl.DataFrame({"ts": ts, "hostname": hosts, "content": lines},
                            schema={"ts": pl.Int64, "hostname": pl.Utf8, "content": pl.Utf8})

    @staticmethod
    def _keys(df):
        return set(df.select(pl.concat_str([pl.col("ts").cast(pl.Utf8), "hostname",
                                            "content"], separator="|"))
                     .to_series().to_list())

    def poll(self):
        """Gera páginas com as linhas novas até agora-lag. O início de cada
        página é inclusivo; as linhas no mesmo ns do cursor já entregues são
        descartadas pela chave (ts, hostname, conteúdo)."""
        end = time.time_ns() - int(self.lag * NS)
        while self.cursor < end:
            raw = self._page(self.cursor, end)
            if raw.height == 0:
                self.cursor, self._seen_at_cursor = end, set()
                return
            full = raw.height >= self.limit
            df = raw
            if self._seen_at_cursor:
                k = raw.select(pl.concat_str([pl.col("ts").cast(pl.Utf8), "hostname",
                                              "content"], separator="|")).to_series()
                df = raw.filter(~k.is_in(list(self._seen_at_cursor)))
            df = df.sort("ts")
            if df.height:
                yield df
            if not full:
                self.cursor, self._seen_at_cursor = end, set()
                return
            last = int(raw["ts"].max())
            at_last = self._keys(raw.filter(pl.col("ts") == last))
            if last == self.cursor:
                if df.height == 0:          # página inteira no mesmo ns, já vista
                    self.cursor, self._seen_at_cursor = last + 1, set()
                    continue
                self._seen_at_cursor |= at_last
            else:
                self._seen_at_cursor = at_last
            self.cursor = last

    def push(self, entries):
        """entries: lista de (labels:dict, ts_ns:int, linha:str)."""
        streams = {}
        for labels, ts, line in entries:
            key = tuple(sorted(labels.items()))
            streams.setdefault(key, []).append([str(ts), line])
        body = {"streams": [{"stream": dict(k), "values": v} for k, v in streams.items()]}
        r = self.s.post(f"{self.url}/loki/api/v1/push", json=body, timeout=self.timeout)
        r.raise_for_status()


class ReplaySource:
    """Reproduz exports gravados como se chegassem em tempo real."""

    def __init__(self, pattern, intervalo_s, velocidade):
        files = sorted(glob.glob(pattern))
        if not files:
            raise SystemExit(f"nenhum arquivo em {pattern}")
        self.data = pl.concat([cf.read_export(f) for f in files]).sort("ts")
        self.t = int(self.data["ts"].min())
        self.tmax = int(self.data["ts"].max())
        self.step, self.vel = int(intervalo_s * NS), velocidade
        print(f"Replay: {len(files)} arquivo(s), {self.data.height:,} linhas, "
              f"{fmt_ts(self.t)} a {fmt_ts(self.tmax)}")

    @property
    def done(self):
        return self.t > self.tmax

    def poll(self):
        b = self.data.filter((pl.col("ts") >= self.t) & (pl.col("ts") < self.t + self.step))
        self.t += self.step
        if b.height:
            yield b

    def sleep(self, intervalo_s):
        if self.vel > 0:
            time.sleep(intervalo_s / self.vel)


def fmt_ts(ns):
    return dt.datetime.fromtimestamp(ns / NS, TZ).strftime("%Y-%m-%d %H:%M:%S")


# =============================================================================
# ALERTAS
# =============================================================================
SEV = {5: "alta", 4: "media", 3: "baixa"}


class AlertAggregator:
    """Um alerta por (hostname, unidade, src_ip, janela de 5 min). Reemite como
    atualização quando o nº de registros anômalos dobra na mesma janela."""

    def __init__(self, models, bucket="5m", cooldown_min=60, min_upd=20):
        self.models, self.bucket, self.min_upd = models, bucket, min_upd
        self.emitted = {}           # chave -> nº de registros no último envio
        self.acc = None             # acumulado da janela corrente
        # Espera por origem: depois de um alerta, a mesma (roteador, origem) só
        # volta a alertar se ESCALAR (mais votos ou volume 2x maior). Evita a
        # repetição causada pelas janelas longas (a contagem de 24 h de um
        # atacante continua alta até virar o dia).
        self.cooldown = dt.timedelta(minutes=cooldown_min)
        self.last_by_src = {}       # (hostname, src_ip) -> (janela, votos, registros)
        self.suprimidos = 0

    def update(self, out):
        an = out.filter(pl.col("anomalo") == 1)
        if an.height == 0:
            return []
        an = an.with_columns(pl.col("dt").dt.truncate(self.bucket).alias("janela"))
        key = ["hostname", "unidade", "src_ip", "janela"]
        pred_cols = [f"pred_{m}" for m in self.models if f"pred_{m}" in an.columns]
        agg = an.group_by(key).agg([
            pl.len().alias("registros"),
            pl.col("ts").min().alias("ts_ini"), pl.col("ts").max().alias("ts_fim"),
            pl.col("dst_port").unique().alias("_portas"),
            pl.col("dst_ip").unique().alias("_destinos"),
            pl.concat_str([pl.col("dst_ip"), pl.col("dst_port").cast(pl.Utf8)], separator=":")
              .unique().head(5).alias("exemplos_destino"),
            pl.col("protocol").mode().first().alias("protocolo"),
            pl.col("direcao").mode().first().alias("direcao"),
            pl.col("votos").max().alias("votos_max"),
            pl.col("fw_flag").max().alias("firewall_detectou"),
            *[pl.col(c).max().alias(c) for c in pred_cols],
        ])
        self.acc = (agg if self.acc is None else
                    pl.concat([self.acc, agg], how="diagonal_relaxed")
                      .group_by(key).agg([
                          pl.col("registros").sum(), pl.col("ts_ini").min(),
                          pl.col("ts_fim").max(),
                          pl.col("_portas").flatten().unique(),
                          pl.col("_destinos").flatten().unique(),
                          pl.col("exemplos_destino").first(),
                          pl.col("protocolo").first(), pl.col("direcao").first(),
                          pl.col("votos_max").max(), pl.col("firewall_detectou").max(),
                          *[pl.col(c).max() for c in pred_cols]]))
        # descarta janelas antigas (> 2 janelas)
        lim = self.acc["janela"].max() - dt.timedelta(minutes=10)
        self.acc = self.acc.filter(pl.col("janela") >= lim)

        alerts = []
        for r in self.acc.iter_rows(named=True):
            k = (r["hostname"], r["unidade"], r["src_ip"], r["janela"])
            prev = self.emitted.get(k)
            # atualização só se o volume dobrou E cresceu um mínimo absoluto
            if prev is not None and (r["registros"] < 2 * prev
                                     or r["registros"] - prev < self.min_upd):
                continue
            ks = (r["hostname"], r["src_ip"])
            last = self.last_by_src.get(ks)
            # espera por origem: outras janelas dentro do período só alertam
            # se o comportamento ESCALAR (mais votos ou volume >= 2x o maior já
            # alertado, com o mínimo absoluto)
            if (last is not None and r["janela"] != last[0]
                    and r["janela"] - last[0] < self.cooldown):
                escalou = (r["votos_max"] > last[1]
                           or (r["registros"] >= 2 * last[2]
                               and r["registros"] - last[2] >= self.min_upd))
                if not escalou:
                    self.suprimidos += 1
                    self.emitted[k] = r["registros"]
                    continue
            self.emitted[k] = r["registros"]
            if last is None or r["janela"] - last[0] >= self.cooldown:
                self.last_by_src[ks] = (r["janela"], r["votos_max"], r["registros"])
            else:
                self.last_by_src[ks] = (last[0], max(last[1], r["votos_max"]),
                                        max(last[2], r["registros"]))
            modelos = [m for m in self.models if r.get(f"pred_{m}")]
            alerts.append({
                "tipo": "novo" if prev is None else "atualizacao",
                "severidade": SEV.get(int(r["votos_max"]), "baixa"),
                "so_ml": not bool(r["firewall_detectou"]),
                "roteador": r["hostname"], "unidade": r["unidade"],
                "origem": r["src_ip"], "direcao": r["direcao"],
                "inicio": fmt_ts(r["ts_ini"]), "fim": fmt_ts(r["ts_fim"]),
                "ts_ini_ns": int(r["ts_ini"]),
                "registros": int(r["registros"]),
                "portas_distintas": len(r["_portas"]),
                "destinos_distintos": len(r["_destinos"]),
                "exemplos_destino": r["exemplos_destino"], "protocolo": r["protocolo"],
                "votos": int(r["votos_max"]), "modelos": modelos,
            })
        # limpa chaves antigas do controle de emissão
        if len(self.emitted) > 50_000:
            self.emitted = dict(list(self.emitted.items())[-20_000:])
        return alerts


# =============================================================================
def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bundle", required=True)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--loki", help="URL do Loki, ex. http://localhost:3100")
    src.add_argument("--replay", help='glob de exports, ex. "export/*_2026-09-18.txt"')
    p.add_argument("--query", default='{job="mikrotik-firewall"}')
    p.add_argument("--host-label", default="hostname")
    p.add_argument("--intervalo", type=float, default=15, help="segundos entre ciclos")
    p.add_argument("--atraso", type=float, default=5, help="lag de ingestão do Loki (s)")
    p.add_argument("--aquecimento", default="hora", choices=["nenhum", "hora", "dia"])
    p.add_argument("--dedup", default="tolerance", choices=["exact", "tolerance", "none"])
    p.add_argument("--dedup-tol", type=float, default=cf.DEDUP_TOL_S,
                   help="tolerância da dedup em segundos (a mesma usada no export)")
    p.add_argument("--min-votos", type=int, help="sobrepõe o valor do bundle")
    p.add_argument("--saida", default="alertas.jsonl")
    p.add_argument("--push-loki", action="store_true",
                   help='publica alertas no Loki em {job="ml-anomaly"}')
    p.add_argument("--velocidade", type=float, default=0,
                   help="replay: fator de aceleração (0 = o mais rápido possível)")
    p.add_argument("--ataques", help="replay: CSV de ataques para medir latência")
    p.add_argument("--espera-min", type=float, default=60,
                   help="espera por origem após um alerta (minutos; 0 desliga)")
    p.add_argument("--min-atualizacao", type=int, default=20,
                   help="aumento mínimo de registros para reemitir um alerta")
    p.add_argument("--quieto", action="store_true", help="não imprime cada alerta")
    a = p.parse_args()

    eng = InferenceEngine(a.bundle, dedup=None if a.dedup == "none" else a.dedup,
                          dedup_tol_s=a.dedup_tol)
    if a.min_votos:
        eng.min_votes = a.min_votos
    models = list(eng.dets)
    agg = AlertAggregator(models, cooldown_min=a.espera_min, min_upd=a.min_atualizacao)
    print(f"Modelos: {models} | alerta com >= {eng.min_votes} votos")

    if a.loki:
        now = dt.datetime.now(TZ)
        start = {"nenhum": now - dt.timedelta(seconds=a.atraso),
                 "hora": now.replace(minute=0, second=0, microsecond=0),
                 "dia": now.replace(hour=0, minute=0, second=0, microsecond=0)}[a.aquecimento]
        source = LokiSource(a.loki, a.query, a.host_label, a.atraso,
                            start_ns=int(start.timestamp() * NS))
        print(f"Loki {a.loki} | aquecimento desde {start:%H:%M:%S}")
    else:
        source = ReplaySource(a.replay, a.intervalo, a.velocidade)

    out_f = open(a.saida, "a", encoding="utf-8")
    stop = {"flag": False}
    signal.signal(signal.SIGINT, lambda *_: stop.update(flag=True))
    signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))
    all_alerts, cycle = [], 0

    while not stop["flag"]:
        t_cycle = time.perf_counter()
        n_lines, n_alerts = 0, 0
        try:
            for page in source.poll():
                out = eng.process(page)
                n_lines += page.height
                if out is None:
                    continue
                alerts = agg.update(out)
                for al in alerts:
                    out_f.write(json.dumps(al, ensure_ascii=False, default=str) + "\n")
                    if not a.quieto:
                        tag = "SÓ ML" if al["so_ml"] else "ML+FW"
                        print(f"  [{al['severidade'].upper():5s}|{tag}] {al['inicio']} "
                              f"{al['unidade']} origem={al['origem']} {al['direcao']} "
                              f"reg={al['registros']} portas={al['portas_distintas']} "
                              f"destinos={al['destinos_distintos']} votos={al['votos']} "
                              f"({al['tipo']})")
                if alerts and a.push_loki and a.loki:
                    try:
                        source.push([({"job": "ml-anomaly", "fonte": "realtime-scanner",
                                       "unidade": al["unidade"],
                                       "severidade": al["severidade"]},
                                      time.time_ns(), json.dumps(al, ensure_ascii=False,
                                                                 default=str))
                                     for al in alerts])
                    except Exception as e:
                        print(f"  ! falha no push para o Loki: {e}")
                all_alerts += alerts
                n_alerts += len(alerts)
        except Exception as e:
            print(f"  ! erro no ciclo: {e}")
        out_f.flush()
        cycle += 1
        dt_c = time.perf_counter() - t_cycle
        if a.loki or cycle % 240 == 0 or n_alerts:
            print(f"[ciclo {cycle}] linhas={n_lines:,} alertas={n_alerts} "
                  f"tempo={1000*dt_c:.0f} ms estado={eng.state.size():,} chaves")
        if a.replay:
            if source.done:
                break
            source.sleep(a.intervalo)
        else:
            time.sleep(max(0.0, a.intervalo - dt_c))

    out_f.close()
    s = eng.stats
    print(f"\nFim. Lotes={s['lotes']:,} entrada={s['entrada']:,} "
          f"duplicadas={s['duplicadas']:,} anômalos={s['anomalas']:,} "
          f"alertas={len(all_alerts)} (suprimidos pela espera: {agg.suprimidos}) -> {a.saida}")
    base = os.path.splitext(a.saida)[0]
    lat = None
    if a.replay and a.ataques:
        lat, fora = report_latency(all_alerts, cf.read_attack_windows(a.ataques), source.data)
        lat.write_csv(base + "_latencia_por_evento.csv")
    resumo_alertas(all_alerts, base + "_resumo.json",
                   fora if lat is not None else None, agg.suprimidos)


def report_latency(alerts, aw, data=None):
    """Latência de detecção por evento, no tempo dos dados: do início do ataque
    até o primeiro registro anômalo alertado daquela origem. Só entram os
    eventos cuja origem aparece nos dados reproduzidos, dentro da janela."""
    print("\nLatência de detecção por evento (tempo dos dados):")
    rows = []
    for w in aw.iter_rows(named=True):
        s = w["start"].replace(tzinfo=TZ).timestamp() * NS
        e = w["end"].replace(tzinfo=TZ).timestamp() * NS
        if data is not None and data.filter(
                (pl.col("ts") >= s) & (pl.col("ts") <= e)
                & pl.col("content").str.contains(w["src_ip"] + ":", literal=True)).height == 0:
            continue
        hits = [al for al in alerts if al["origem"] == w["src_ip"]
                and s <= al["ts_ini_ns"] <= e]
        first = min((al["ts_ini_ns"] for al in hits), default=None)
        por_k = {}
        for k in (4, 5):
            fk = min((al["ts_ini_ns"] for al in hits if al["votos"] >= k), default=None)
            por_k[f"detectado_{k}v"] = fk is not None
            por_k[f"latencia_{k}v_s"] = None if fk is None else round((fk - s) / NS, 1)
        lat = None if first is None else (first - s) / NS
        so_ml = any(al["so_ml"] for al in hits)
        rows.append({"evento": len(rows)}
                    | {k: w.get(k) for k in ("tipo", "regime", "origem", "gerador") if k in w}
                    | {"detectado": first is not None,
                       "latencia_s": None if lat is None else round(lat, 1),
                       "alertas": len(hits), "algum_so_ml": so_ml} | por_k)
    with pl.Config(tbl_cols=10, tbl_width_chars=140):
        print(pl.DataFrame(rows))
    inside = set()
    for w in aw.iter_rows(named=True):
        s = w["start"].replace(tzinfo=TZ).timestamp() * NS
        e = w["end"].replace(tzinfo=TZ).timestamp() * NS
        inside |= {id(al) for al in alerts if al["origem"] == w["src_ip"]
                   and s <= al["ts_ini_ns"] <= e}
    fora = [al for al in alerts if id(al) not in inside and al["tipo"] == "novo"]
    print(f"Alertas fora das janelas de ataque (candidatos a falso positivo ou "
          f"eventos reais desconhecidos): {len(fora)}")
    return pl.DataFrame(rows), fora


def resumo_alertas(alerts, path, fora, suprimidos):
    """Resumo agregado dos alertas, SEM IPs, para o capítulo 5."""
    novos = [al for al in alerts if al["tipo"] == "novo"]
    dias = {al["inicio"][:10] for al in alerts}
    por = lambda campo, lst: dict(sorted(
        {k: sum(1 for al in lst if al[campo] == k) for k in {al[campo] for al in lst}}.items()))
    res = {
        "alertas_total": len(alerts), "alertas_novos": len(novos),
        "atualizacoes": len(alerts) - len(novos), "suprimidos_pela_espera": suprimidos,
        "dias_com_alerta": len(dias),
        "alertas_novos_por_dia": round(len(novos) / max(len(dias), 1), 2),
        "novos_por_severidade": por("severidade", novos),
        "novos_por_unidade": por("unidade", novos),
        "novos_por_direcao": por("direcao", novos),
        "fracao_so_ml": round(sum(al["so_ml"] for al in novos) / max(len(novos), 1), 3),
    }
    if fora is not None:
        res["novos_fora_das_janelas_de_ataque"] = len(fora)
        res["novos_fora_das_janelas_por_dia"] = round(len(fora) / max(len(dias), 1), 2)
    base = fora if fora is not None else novos
    res["pontos_de_operacao"] = {
        f">={k}_votos": {
            "alertas_por_dia": round(sum(1 for al in base if al["votos"] >= k) / max(len(dias), 1), 2),
            "origens_distintas_por_dia": round(len({(al["inicio"][:10], al["origem"]) for al in base
                                                    if al["votos"] >= k}) / max(len(dias), 1), 2),
        } for k in (3, 4, 5)}
    res["pontos_de_operacao"]["obs"] = ("contados fora das janelas de ataque" if fora is not None
                                        else "contados sobre todos os alertas novos")
    json.dump(anon_obj(res), open(path, "w"), indent=2, ensure_ascii=False)
    print(f"Resumo dos alertas: {path}")


def anon_str(x):
    """Troca nomes reais de secretarias e roteadores pelos rótulos anônimos."""
    for real, fake in sorted({**cf.HOST_ANON, **cf.UNIT_ANON}.items(),
                             key=lambda kv: -len(kv[0])):
        x = x.replace(real, cf.UNIT_ANON.get(real, fake) if real in cf.UNIT_ANON else fake)
    return x


def anon_obj(o):
    if isinstance(o, dict):
        return {anon_str(k) if isinstance(k, str) else k: anon_obj(v) for k, v in o.items()}
    if isinstance(o, list):
        return [anon_obj(v) for v in o]
    return anon_str(o) if isinstance(o, str) else o


if __name__ == "__main__":
    main()
