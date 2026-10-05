#!/usr/bin/env python3
"""
=============================================================================
inference.py — Motor de inferência (usado pelo teste e pelo scanner)
=============================================================================
InferenceEngine.process(lote) recebe linhas brutas no formato
    (ts em ns, hostname, content)
exatamente como vêm da API do Loki, e devolve cada registro com:
    escores e predições de cada detector, nº de votos e 'anomalo' (ensemble),
    unidade, direção, fw_flag e as colunas de identificação do tráfego.

Etapas (tempos medidos por etapa em self.last_timings):
    dedup      remove duplicatas do syslog, inclusive entre lotes
    parse      mesmo parser do treino (common_features_polars.parse_frame)
    unidade    secretaria/direção (add_unit_columns)
    janelas    features de janela CAUSAIS via WindowState (idênticas às do treino)
    features   build_features com os encoders do treino
    <modelo>   pontuação de cada detector
=============================================================================
"""
import time
import numpy as np
import polars as pl
import joblib

import common_features_polars as cf
import models as M  # noqa: F401  (necessário para o joblib reconstruir os detectores)

META = ["ts", "dt", "hostname", "unidade", "direcao", "entre_unidades", "chain",
        "prefix", "protocol", "flags_raw", "src_ip", "src_port", "dst_ip", "dst_port",
        "pkt_len", "iface_in", "iface_out", "fw_flag"]


class InferenceEngine:
    def __init__(self, bundle, dedup="tolerance", dedup_tol_s=cf.DEDUP_TOL_S, models=None):
        self.b = joblib.load(bundle) if isinstance(bundle, str) else bundle
        if not self.b.get("causal", False):
            raise ValueError("bundle treinado com janelas não causais; "
                             "re-exporte os Parquet (v4) e treine de novo")
        self.dets = {n: d for n, d in self.b["detectors"].items()
                     if models is None or n in models}
        self.min_votes = min(self.b["min_votes"], len(self.dets))
        self.dedup, self.tol = dedup, dedup_tol_s
        self.state = cf.WindowState(self.b["windows"])
        self._tail = None           # chaves de dedup recentes (entre lotes)
        self.last_timings = {}
        self.stats = {"lotes": 0, "entrada": 0, "duplicadas": 0, "processadas": 0,
                      "anomalas": 0}

    # ------------------------------------------------------------------ dedup
    def _dedup(self, raw):
        """Mesma regra de common_features_polars.dedup_frame, estendida entre
        lotes: guarda o último instante de cada (hostname, conteúdo) visto nos
        últimos segundos e compara a primeira ocorrência do lote novo com ele."""
        if self.dedup is None:
            return raw
        if self.dedup == "exact":
            key = ["hostname", "ts", "content"]
            d = raw.unique(subset=key, keep="first", maintain_order=True)
            if self._tail is not None and self._tail.height:
                d = d.join(self._tail, on=key, how="anti")
            if d.height:
                tmax = d["ts"].max()
                t = d.select(key) if self._tail is None else pl.concat([self._tail, d.select(key)])
                self._tail = t.filter(pl.col("ts") >= tmax)
            return d
        tol = int(self.tol * 1e9)
        x = raw.select(["ts", "hostname", "content"]).with_row_index("_o").with_columns(
            pl.lit(False).alias("_old"))
        if self._tail is not None and self._tail.height:
            x = pl.concat([self._tail.with_columns([pl.lit(None, dtype=pl.UInt32).alias("_o"),
                                                    pl.lit(True).alias("_old")])
                                    .select(x.columns), x])
        x = (x.sort(["hostname", "content", "ts"])
              .with_columns(pl.col("ts").diff().over(["hostname", "content"]).alias("_dt")))
        keep = x.filter(~pl.col("_old")
                        & (pl.col("_dt").is_null() | (pl.col("_dt") >= tol))).get_column("_o")
        # estado: último instante de cada conteúdo (inclui as linhas descartadas,
        # como no cálculo offline, que compara com a linha anterior qualquer)
        tmax = x["ts"].max()
        self._tail = (x.filter(pl.col("ts") >= tmax - 2 * tol - 1_000_000_000)
                       .group_by(["hostname", "content"]).agg(pl.col("ts").max())
                       .select(["ts", "hostname", "content"]))
        return raw.with_row_index("_o").filter(pl.col("_o").is_in(keep)).drop("_o")

    # ---------------------------------------------------------------- process
    def process(self, raw):
        T = {}
        t = time.perf_counter()
        n_in = raw.height
        raw = raw.with_columns(pl.col("ts").cast(pl.Int64))
        d = self._dedup(raw)
        T["dedup"] = time.perf_counter() - t
        self.stats["lotes"] += 1
        self.stats["entrada"] += n_in
        self.stats["duplicadas"] += n_in - d.height
        if d.height == 0:
            self.last_timings = T
            return None

        t = time.perf_counter()
        df = cf.parse_frame(d, verbose=False)
        T["parse"] = time.perf_counter() - t
        if df.height == 0:
            self.last_timings = T
            return None

        t = time.perf_counter()
        df = cf.add_unit_columns(df, self.b.get("unit_map"), self.b.get("wan_ifaces"))
        T["unidade"] = time.perf_counter() - t

        t = time.perf_counter()
        df = self.state.update(df)
        T["janelas"] = time.perf_counter() - t

        t = time.perf_counter()
        X, feats, _ = cf.build_features(df, encoders=self.b["encoders"],
                                        windows=self.b["windows"], verbose=False)
        if feats != self.b["features"]:
            raise RuntimeError("lista de features difere da usada no treino")
        Xs = self.b["scaler"].transform(X).astype(np.float32)
        T["features"] = time.perf_counter() - t

        cols, preds = {}, {}
        for n, det in self.dets.items():
            t = time.perf_counter()
            s = det.score(Xs)
            p = det.predict(Xs, s)
            T[n] = time.perf_counter() - t
            cols[f"score_{n}"] = s
            cols[f"pred_{n}"] = p
            preds[n] = p
        votes = np.sum(np.vstack(list(preds.values())), axis=0).astype(np.int8)
        out = (df.select([c for c in META if c in df.columns])
                 .with_columns([pl.Series(k, v) for k, v in cols.items()]
                               + [pl.Series("votos", votes),
                                  pl.Series("anomalo",
                                            (votes >= self.min_votes).astype(np.int8))]))
        self.stats["processadas"] += out.height
        self.stats["anomalas"] += int(out["anomalo"].sum())
        self.last_timings = T
        self.last_X = X
        return out

    def unknown_categories(self, df):
        """Fração de valores categóricos fora do vocabulário do treino."""
        res = {}
        for c, vocab in self.b["encoders"].items():
            if c in df.columns:
                v = df.get_column(c)
                unk = ~v.is_in(vocab) & v.is_not_null()
                res[c] = {"fracao": float(unk.mean()),
                          "exemplos": v.filter(unk).unique().head(5).to_list()}
        return res
