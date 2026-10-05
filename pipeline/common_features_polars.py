#!/usr/bin/env python3
"""
=============================================================================
common_features_polars.py — v2
=============================================================================
Parsing + engenharia de features com Polars para os logs de firewall MikroTik.

Mudanças em relação à v1 (ver comentários "v2:" no código):
  1. Parser aceita TCP, UDP e ICMP, chains forward/input/output, src-mac
     opcional e NAT. A v1 só aceitava TCP em 'forward' e descartava o resto,
     inclusive as linhas de ataque (chain=input).
  2. Features de frequência calculadas em JANELAS DE TEMPO (5min, 1h, 24h)
     por (hostname, src_ip), e fan-in por destino. A v1 calculava sobre o
     dataset inteiro, o que apaga ataques lentos (low-and-slow).
  3. Encoding categórico ESTÁVEL (vocabulário salvo e reutilizável). Na v1 o
     código dependia da ordem de aparição -> modelo e inferência divergiam.
  4. Horário/dia da semana no fuso local (America/Sao_Paulo). A v1 usava UTC
     (3h adiantado) e o "dia 0" era quinta-feira.
  5. 'fw_flag' (detecção do firewall) separado do ground truth 'is_atk'.
     O ground truth vem das janelas de ataque (ataques_horarios / label_join),
     NUNCA do prefixo do firewall: avaliar o ML contra o que o firewall já
     detectou seria circular, justamente o oposto da tese.
  6. Hostname preservado (terceira coluna do export ou nome do arquivo).
  7. Amostragem estratificada corrigida e feita POR ARQUIVO/DIA, depois das
     features de janela (amostrar antes deflaciona as contagens).
  8. Features de identidade (octetos de IP, MAC) desligadas por padrão.

Mudanças da v3:
  9. Coluna 'unidade' (secretaria): roteadores compartilhados por mais de
     uma secretaria são desmembrados pela bridge (UNIT_MAP / WAN_IFACES),
     com 'direcao' do tráfego e marcação de tráfego entre unidades.
 10. export_to_parquet(): parse + dedup + unidade + janelas UMA vez por
     arquivo (dia/roteador), salvo em Parquet/zstd. Tudo o que vem depois
     (estatística descritiva, amostragem, treino) lê do Parquet.
 11. descriptive_stats(): total, média e desvio-padrão do volume horário
     por dia, unidade, hora e protocolo, direto dos Parquet (lazy).

Mudanças da v4 (treino + inferência em tempo real):
 12. Parsing separado em read_export() / dedup_frame() / parse_frame(), para
     reaproveitar o mesmo código com linhas vindas da API do Loki.
 13. Janelas CAUSAIS (padrão): cada registro recebe as contagens acumuladas
     ATÉ ele na janela corrente, e não o total da janela. É o que existe em
     tempo real; evita divergência entre treino e serviço.
 14. WindowState: calcula incrementalmente, lote a lote, exatamente as mesmas
     features de janela causais (usado pelo scanner em tempo real).
 15. label_ground_truth() numera os eventos (atk_evento) e copia colunas
     extras do arquivo de ataques (ex.: regime, origem) como atk_<coluna>.

Interface mantida para os benchmarks:
  build_features(df) -> (X float32, feature_names, df_pandas)

Formatos de entrada aceitos (.txt ou .txt.gz):
  <timestamp_ns>\t<linha>                 (hostname via parâmetro ou nome do arquivo)
  <timestamp_ns>\t<hostname>\t<linha>     (recomendado)

Diagnóstico de cobertura do parser:
  python common_features_polars.py arquivo.txt [max_linhas]
=============================================================================
"""

import os
import re
import gzip
import numpy as np
import polars as pl

SUSPICIOUS_PORTS = [21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5900, 8291]
TZ = "America/Sao_Paulo"
WINDOWS = ("5m", "1h", "1d")   # 1d = dia local (00:00-23:59)

# v2: regex genérico para qualquer chain/protocolo do log de firewall RouterOS.
#   TCP:  proto TCP (SYN), 1.2.3.4:5->6.7.8.9:10, len 60
#   UDP:  proto UDP, 1.2.3.4:5->6.7.8.9:10, len 76
#   ICMP: proto ICMP (type 8, code 0), 1.2.3.4->6.7.8.9, len 84
#   input: out:(unknown 0) | src-mac pode não existir | NAT (...)->... opcional
RE_LOG = (
    r"^(?P<prefix>.*?)\s*(?P<chain>forward|input|output): "
    r"in:(?P<iface_in>\S+) out:(?P<iface_out>\(unknown 0\)|\S+), "
    r"(?:src-mac (?P<src_mac>[0-9a-fA-F:]+), )?"
    r"proto (?P<protocol>[A-Za-z0-9-]+)(?: \((?P<flags_raw>[^)]*)\))?, "
    r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)(?::(?P<src_port>\d+))?->"
    r"(?P<dst_ip>\d+\.\d+\.\d+\.\d+)(?::(?P<dst_port>\d+))?"
    r"(?:, NAT [^,]+)?, len (?P<pkt_len>\d+)"
)

# Prefixos das regras de detecção do firewall (aplicado só ao prefixo)
RE_FW_FLAG = r"_atk|\[LAB-|PORT-SCAN|SYN-FLOOD|BRUTE|BLACKLIST"

RE_PRIVATE = r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)"

# ---------------------------------------------------------------------------
# v3: mapeamento de unidades (secretarias). EDITE conforme a rede.
#   chave (hostname, interface) -> unidade; (hostname, "*") vale para todas as
#   interfaces internas do roteador sem regra específica.
#   Os nomes reais ficam só aqui; anonimize na hora de gerar tabelas/figuras
#   (ver UNIT_ANON).
# ---------------------------------------------------------------------------
UNIT_MAP = {
    ("ROTEADOR_1", "*"): "SEC_A",
    ("ROTEADOR_2", "bridgeSEC_B"): "SEC_B",
    ("ROTEADOR_2", "bridgeSEC_C"): "SEC_C",
    # interface interna sem vínculo identificado com uma secretaria:
    # tratada como infraestrutura compartilhada (fica no treino, fora da
    # comparação entre secretarias)
    ("ROTEADOR_2", "bridgeInterna"): "INFRA_R2",
    # TODO: acrescentar as demais secretarias/roteadores
}
# Interfaces de saída para a internet (WAN) de cada roteador
WAN_IFACES = {
    "ROTEADOR_1": ["bridgeWAN"],
    "ROTEADOR_2": ["ether1"],
}
# Nomes anonimizados para o texto público do TCC (LGPD / divulgação
# responsável). TUDO que vai para tabela ou figura passa por anonymize().
UNIT_ANON = {"SEC_A": "Secretaria A", "SEC_B": "Secretaria B",
             "SEC_C": "Secretaria C", "INFRA_R2": "Infraestrutura compartilhada"}
# Unidades que não entram na comparação entre secretarias (continuam no treino)
UNIT_FORA_COMPARACAO = {"INFRA_R2"}
HOST_ANON = {"ROTEADOR_1": "Roteador 1", "ROTEADOR_2": "Roteador 2"}

# Nome de arquivo "HOSTNAME_AAAA-MM-DD.txt[.gz]" -> hostname
RE_HOST_FROM_NAME = re.compile(r"^(?P<host>.+?)_\d{4}-\d{2}-\d{2}")


# --------------------------------------------------------------------------
# Leitura e parsing
# --------------------------------------------------------------------------
def _host_from_filename(path):
    m = RE_HOST_FROM_NAME.match(os.path.basename(path))
    return m.group("host") if m else None


def read_export(path, hostname=None, max_lines=None):
    """Lê o export do Loki -> DataFrame (ts, hostname, content)."""
    if hostname is None:
        hostname = _host_from_filename(path)
    df = pl.read_csv(
        path, separator="\x01", has_header=False, new_columns=["line"],
        quote_char=None, truncate_ragged_lines=True, low_memory=True,
    )
    if max_lines:
        df = df.head(max_lines)
    # aceita 2 ou 3 colunas separadas por TAB
    return (
        df.with_columns(
            pl.col("line").str.splitn("\t", 3)
              .struct.rename_fields(["f0", "f1", "f2"]).alias("p"))
          .unnest("p")
          .with_columns([
              pl.when(pl.col("f1").is_null()).then(None)
                .otherwise(pl.col("f0")).alias("ts_raw"),
              pl.when(pl.col("f2").is_not_null()).then(pl.col("f1"))
                .otherwise(pl.lit(hostname, dtype=pl.Utf8)).alias("hostname"),
              pl.when(pl.col("f2").is_not_null()).then(pl.col("f2"))
                .when(pl.col("f1").is_not_null()).then(pl.col("f1"))
                .otherwise(pl.col("f0")).alias("content"),
          ])
          .drop(["line", "f0", "f1", "f2"])
          .with_columns(pl.col("ts_raw").cast(pl.Int64, strict=False)
                          .fill_null(0).alias("ts"))
          .drop("ts_raw")
          .select(["ts", "hostname", "content"])
    )


# Tolerância da dedup. Nos dados do órgão (24/09/2026), as repetições em menos de
# 1 ms concentram-se em TCP ACK e UDP (tráfego legítimo) e são praticamente nulas
# em TCP SYN (0,09%), controle em que uma repetição legítima não ocorre: não há
# duplicação sistemática nos logs de tráfego. Por isso, 0 = sem dedup.
DEDUP_TOL_S = 0.0


def dedup_frame(df, dedup="tolerance", dedup_tol_s=DEDUP_TOL_S):
    """Remove duplicatas do syslog.

    "tolerance": uma linha é duplicata se a linha ANTERIOR com o mesmo
        (hostname, conteúdo) chegou há menos de dedup_tol_s segundos.
        Cópias do syslog chegam praticamente juntas; repetições legítimas
        (ex.: ACKs de uma mesma conexão, que geram linhas idênticas) vêm
        espaçadas pelo tempo de ida e volta da rede. Por isso a tolerância
        deve ser pequena (ordem de ms), escolhida pelo histograma de
        diagnose_duplicates(). NÃO use 1 s: apagaria tráfego legítimo.
    "exact": mesmo hostname, conteúdo e timestamp idêntico em ns.
    None: sem dedup.
    """
    if dedup is None:
        return df
    if dedup == "exact":
        return df.unique(subset=["hostname", "ts", "content"], keep="first",
                         maintain_order=True)
    tol = int(dedup_tol_s * 1e9)
    return (df.with_row_index("_o")
              .sort(["hostname", "content", "ts"])
              .with_columns(pl.col("ts").diff().over(["hostname", "content"]).alias("_dt"))
              .filter(pl.col("_dt").is_null() | (pl.col("_dt") >= tol))
              .sort("_o").drop(["_o", "_dt"]))


def parse_frame(df, verbose=True):
    """(ts, hostname, content) -> registros estruturados. Linhas que não
    casam com RE_LOG são descartadas (e contadas)."""
    log = print if verbose else (lambda *a, **k: None)
    df = df.hstack(
        df.select(pl.col("content").str.extract_groups(RE_LOG).alias("g"))
          .unnest("g")
    )
    unparsed = df.filter(pl.col("src_ip").is_null())
    df = df.filter(pl.col("src_ip").is_not_null())
    log(f"  [polars] Parseadas: {df.height:,} | não parseadas: {unparsed.height:,}")
    if unparsed.height and verbose:
        for x in unparsed.get_column("content").head(3).to_list():
            log(f"      ex. não parseada: {x[:160]}")
    return df.with_columns([
        pl.col("src_port").cast(pl.Int32, strict=False).fill_null(0),
        pl.col("dst_port").cast(pl.Int32, strict=False).fill_null(0),
        pl.col("pkt_len").cast(pl.Int32, strict=False).fill_null(0),
        pl.col("flags_raw").fill_null(""),
        pl.col("prefix").fill_null(""),
        # detecção do firewall != ground truth
        pl.col("prefix").fill_null("").str.contains(RE_FW_FLAG)
          .cast(pl.Int8).alias("fw_flag"),
        # ground truth: preenchido por label_ground_truth()
        pl.lit(0, dtype=pl.Int8).alias("is_atk"),
        # datetime no fuso local, sem tz (Brasil sem horário de verão)
        pl.from_epoch(pl.col("ts"), time_unit="ns")
          .dt.replace_time_zone("UTC").dt.convert_time_zone(TZ)
          .dt.replace_time_zone(None).alias("dt"),
    ]).drop("content")


def load_and_parse(path, hostname=None, max_lines=None, dedup="tolerance",
                   dedup_tol_s=DEDUP_TOL_S, verbose=True):
    """Lê o export do Loki e devolve um DataFrame Polars estruturado.
    Ver dedup_frame() para os modos de dedup (meça com diagnose_duplicates)."""
    log = print if verbose else (lambda *a, **k: None)
    log(f"  [polars] Lendo {path}...")
    df = read_export(path, hostname, max_lines)
    log(f"  [polars] Linhas lidas: {df.height:,}")
    before = df.height
    df = dedup_frame(df, dedup, dedup_tol_s)
    if dedup:
        log(f"  [polars] Dedup ({dedup}): removidas {before - df.height:,}")
    df = parse_frame(df, verbose)
    log(f"  [polars] Linhas com detecção do firewall (fw_flag): "
        f"{int(df.get_column('fw_flag').sum()):,}")
    return df


def diagnose_duplicates(path, max_lines=2_000_000):
    """Histograma do intervalo entre linhas CONSECUTIVAS de conteúdo idêntico.
    As cópias do syslog formam um pico em intervalos muito curtos; as
    repetições legítimas ficam na faixa do tempo de ida e volta da rede
    (ms a centenas de ms). Escolha dedup_tol_s no vale entre os dois."""
    raw = read_export(path, max_lines=max_lines)
    d = (raw.sort(["hostname", "content", "ts"])
            .with_columns(pl.col("ts").diff().over(["hostname", "content"]).alias("dt"))
            .filter(pl.col("dt").is_not_null()))
    edges = [0, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 1_000_000_000, None]
    names = ["< 10 µs", "10–100 µs", "0,1–1 ms", "1–10 ms", "10–100 ms", "0,1–1 s", "≥ 1 s"]
    n = raw.height
    print(f"{path}: {n:,} linhas; {d.height:,} repetem uma linha idêntica anterior")
    for (lo, hi), name in zip(zip(edges[:-1], edges[1:]), names):
        m = (pl.col("dt") >= lo) & ((pl.col("dt") < hi) if hi else pl.lit(True))
        k = d.filter(m).height
        print(f"   {name:>10s}: {k:>10,}  ({100*k/n:5.2f}% das linhas)")
    for tol in (0.0001, 0.001, 0.01):
        print(f"   tolerância {tol*1000:g} ms remove "
              f"{n - dedup_frame(raw, 'tolerance', tol).height:,} linhas")


# --------------------------------------------------------------------------
# Ground truth
# --------------------------------------------------------------------------
def label_ground_truth(df, attack_windows):
    """Marca is_atk=1 nas linhas dentro de uma janela de ataque.

    attack_windows: pl.DataFrame com colunas
        start (Datetime, horário local), end (Datetime, horário local),
        src_ip (str), e opcionalmente:
        dst_ip  alvo do ataque. Quando preenchido, só o tráfego da origem PARA
                o alvo é rotulado. Necessário quando a máquina de ataque também
                gera tráfego normal (ex.: a própria estação de coleta).
        regime ("acima"/"abaixo"), origem ("real"/"sintetico"), tipo, etc.
    Gera: is_atk, atk_evento (índice da linha no arquivo de ataques) e
    atk_<coluna> para cada coluna extra.
    """
    base = ("start", "end", "src_ip", "dst_ip")
    extra = [c for c in attack_windows.columns if c not in base]
    has_dst = "dst_ip" in attack_windows.columns
    is_atk = pl.lit(0, dtype=pl.Int8)
    evento = pl.lit(None, dtype=pl.Int32)
    cols = {c: pl.lit(None, dtype=pl.Utf8) for c in extra}
    for i, w in enumerate(attack_windows.iter_rows(named=True)):
        cond = ((pl.col("dt") >= w["start"]) & (pl.col("dt") <= w["end"])
                & (pl.col("src_ip") == w["src_ip"]))
        if has_dst and w["dst_ip"]:
            cond = cond & (pl.col("dst_ip") == w["dst_ip"])
        is_atk = pl.when(cond).then(pl.lit(1, dtype=pl.Int8)).otherwise(is_atk)
        evento = pl.when(cond).then(pl.lit(i, dtype=pl.Int32)).otherwise(evento)
        for c in extra:
            v = None if w[c] is None else str(w[c])
            cols[c] = pl.when(cond).then(pl.lit(v, dtype=pl.Utf8)).otherwise(cols[c])
    return df.with_columns([is_atk.alias("is_atk"), evento.alias("atk_evento")]
                           + [e.alias(f"atk_{c}") for c, e in cols.items()])


def read_attack_windows(path):
    """CSV com colunas start,end,src_ip[,dst_ip,regime,origem,tipo,...];
    datas no horário local, ex. 2026-09-17 14:05:00. dst_ip pode ficar vazio."""
    aw = pl.read_csv(path, try_parse_dates=True,
                     schema_overrides={"src_ip": pl.Utf8, "dst_ip": pl.Utf8})
    for c in ("start", "end"):
        if aw.schema[c] == pl.Utf8:
            aw = aw.with_columns(pl.col(c).str.to_datetime())
    return aw


# --------------------------------------------------------------------------
# Features de janela (o coração da tese: comportamento agregado no tempo)
# --------------------------------------------------------------------------
def _syn_only_expr():
    return ((pl.col("protocol") == "TCP")
            & pl.col("flags_raw").str.contains("SYN")
            & ~pl.col("flags_raw").str.contains("ACK")).cast(pl.Int8)


def add_window_features(df, windows=WINDOWS, causal=True):
    """Para cada janela tumbling (alinhada ao relógio local), por
    (hostname, src_ip): nº de conexões, portas de destino distintas, IPs de
    destino distintos, razão de SYN sem ACK; e por (hostname, dst_ip): nº de
    origens distintas (fan-in, para ataques distribuídos).

    causal=True (padrão): valores ACUMULADOS até o registro, na janela
      corrente — é o que o scanner em tempo real consegue calcular
      (WindowState produz exatamente os mesmos números).
    causal=False: total da janela inteira (versão da v2/v3; só serve para
      análise retrospectiva, NÃO para treinar o modelo usado em tempo real).

    Contagens em log1p. Rodar sobre o dia/arquivo COMPLETO, antes de amostrar.
    """
    if "syn_only" not in df.columns:
        df = df.with_columns(_syn_only_expr().alias("syn_only"))
    if causal:
        df = df.sort("ts", maintain_order=True)
    for w in windows:
        b = f"_b_{w}"
        ks = ["hostname", "src_ip", b]
        kd = ["hostname", "dst_ip", b]
        df = df.with_columns(pl.col("dt").dt.truncate(w).alias(b))
        if causal:
            n = pl.int_range(1, pl.len() + 1).over(ks)
            exprs = [
                n.log1p().alias(f"src_n_{w}"),
                pl.col("dst_port").is_first_distinct().cast(pl.Int64)
                  .cum_sum().over(ks).log1p().alias(f"src_uports_{w}"),
                pl.col("dst_ip").is_first_distinct().cast(pl.Int64)
                  .cum_sum().over(ks).log1p().alias(f"src_udst_{w}"),
                (pl.col("syn_only").cast(pl.Int64).cum_sum().over(ks)
                 / n).alias(f"src_synr_{w}"),
                pl.col("src_ip").is_first_distinct().cast(pl.Int64)
                  .cum_sum().over(kd).log1p().alias(f"dst_usrc_{w}"),
            ]
        else:
            exprs = [
                pl.len().over(ks).log1p().alias(f"src_n_{w}"),
                pl.col("dst_port").n_unique().over(ks).log1p().alias(f"src_uports_{w}"),
                pl.col("dst_ip").n_unique().over(ks).log1p().alias(f"src_udst_{w}"),
                pl.col("syn_only").mean().over(ks).alias(f"src_synr_{w}"),
                pl.col("src_ip").n_unique().over(kd).log1p().alias(f"dst_usrc_{w}"),
            ]
        df = df.with_columns(exprs).drop(b)
    return df


class WindowState:
    """Estado incremental das features de janela causais, para uso em tempo
    real. Cada chamada a update(lote) devolve o lote com as mesmas colunas
    que add_window_features(causal=True) produziria se o histórico inteiro
    estivesse disponível. Os lotes devem chegar em ordem de tempo.

    Guarda, por janela, só o bucket corrente e o anterior: contagens e
    conjuntos de (portas, destinos, origens) distintos já vistos.
    """

    def __init__(self, windows=WINDOWS):
        self.windows = tuple(windows)
        e = lambda sch: pl.DataFrame(schema=sch)
        base = {"hostname": pl.Utf8, "src_ip": pl.Utf8, "_b": pl.Datetime("ns")}
        based = {"hostname": pl.Utf8, "dst_ip": pl.Utf8, "_b": pl.Datetime("ns")}
        self.cnt = {w: e({**base, "_n0": pl.Int64, "_s0": pl.Int64,
                          "_p0": pl.Int64, "_d0": pl.Int64}) for w in self.windows}
        self.fan = {w: e({**based, "_f0": pl.Int64}) for w in self.windows}
        self.sp = {w: e({**base, "dst_port": pl.Int32}) for w in self.windows}
        self.sd = {w: e({**base, "dst_ip": pl.Utf8}) for w in self.windows}
        self.ds = {w: e({**based, "src_ip": pl.Utf8}) for w in self.windows}

    def size(self):
        return sum(t.height for d in (self.sp, self.sd, self.ds) for t in d.values())

    def update(self, df):
        if "syn_only" not in df.columns:
            df = df.with_columns(_syn_only_expr().alias("syn_only"))
        df = df.sort("ts", maintain_order=True).with_row_index("_i")
        ks = ["hostname", "src_ip", "_b"]
        kd = ["hostname", "dst_ip", "_b"]
        for w in self.windows:
            d = df.select(["_i", "hostname", "src_ip", "dst_ip", "dst_port",
                           "syn_only", "dt"]).with_columns(
                pl.col("dt").dt.truncate(w).cast(pl.Datetime("ns")).alias("_b"))
            mark = lambda t: t.with_columns(pl.lit(1, dtype=pl.Int8).alias("_k"))
            d = (d.join(self.cnt[w], on=ks, how="left")
                  .join(self.fan[w], on=kd, how="left")
                  .join(mark(self.sp[w]), on=ks + ["dst_port"], how="left")
                  .rename({"_k": "_kp"})
                  .join(mark(self.sd[w]), on=ks + ["dst_ip"], how="left")
                  .rename({"_k": "_kd"})
                  .join(mark(self.ds[w]), on=kd + ["src_ip"], how="left")
                  .rename({"_k": "_ks"})
                  .sort("_i")
                  .with_columns([pl.col(c).fill_null(0)
                                 for c in ("_n0", "_s0", "_p0", "_d0", "_f0")]))
            d = d.with_columns([
                (pl.col("dst_port").is_first_distinct().over(ks)
                 & pl.col("_kp").is_null()).cast(pl.Int64).alias("_np"),
                (pl.col("dst_ip").is_first_distinct().over(ks)
                 & pl.col("_kd").is_null()).cast(pl.Int64).alias("_nd"),
                (pl.col("src_ip").is_first_distinct().over(kd)
                 & pl.col("_ks").is_null()).cast(pl.Int64).alias("_ns"),
            ])
            n = pl.col("_n0") + pl.int_range(1, pl.len() + 1).over(ks)
            d = d.with_columns([
                n.alias("_n"),
                (pl.col("_s0") + pl.col("syn_only").cast(pl.Int64).cum_sum().over(ks)).alias("_s"),
                (pl.col("_p0") + pl.col("_np").cum_sum().over(ks)).alias("_p"),
                (pl.col("_d0") + pl.col("_nd").cum_sum().over(ks)).alias("_d"),
                (pl.col("_f0") + pl.col("_ns").cum_sum().over(kd)).alias("_f"),
            ])
            feats = d.select([
                pl.col("_n").log1p().alias(f"src_n_{w}"),
                pl.col("_p").log1p().alias(f"src_uports_{w}"),
                pl.col("_d").log1p().alias(f"src_udst_{w}"),
                (pl.col("_s") / pl.col("_n")).alias(f"src_synr_{w}"),
                pl.col("_f").log1p().alias(f"dst_usrc_{w}"),
            ])
            df = df.drop([c for c in feats.columns if c in df.columns]).hstack(feats)

            # ---- atualiza o estado
            agg = d.group_by(ks).agg([
                pl.len().alias("n"), pl.col("syn_only").cast(pl.Int64).sum().alias("s"),
                pl.col("_np").sum().alias("p"), pl.col("_nd").sum().alias("dd")])
            self.cnt[w] = (pl.concat([
                    self.cnt[w],
                    agg.select(ks + [pl.col("n").alias("_n0"), pl.col("s").alias("_s0"),
                                     pl.col("p").alias("_p0"), pl.col("dd").alias("_d0")])],
                    how="vertical_relaxed")
                .group_by(ks).agg([pl.col(c).sum() for c in ("_n0", "_s0", "_p0", "_d0")]))
            fagg = d.group_by(kd).agg(pl.col("_ns").sum().alias("_f0"))
            self.fan[w] = (pl.concat([self.fan[w], fagg], how="vertical_relaxed")
                             .group_by(kd).agg(pl.col("_f0").sum()))
            self.sp[w] = pl.concat([self.sp[w], d.filter(pl.col("_np") == 1)
                                    .select(ks + ["dst_port"])], how="vertical_relaxed")
            self.sd[w] = pl.concat([self.sd[w], d.filter(pl.col("_nd") == 1)
                                    .select(ks + ["dst_ip"])], how="vertical_relaxed")
            self.ds[w] = pl.concat([self.ds[w], d.filter(pl.col("_ns") == 1)
                                    .select(kd + ["src_ip"])], how="vertical_relaxed")

            # ---- descarta buckets antigos (mantém o corrente e o anterior)
            cur = d.get_column("_b").max()
            if cur is not None:
                prev = pl.select(pl.lit(cur).dt.offset_by(f"-{w}")).item()
                keep = pl.col("_b") >= prev
                for tab in (self.cnt, self.fan, self.sp, self.sd, self.ds):
                    tab[w] = tab[w].filter(keep)
        return df.drop("_i")


def window_feature_names(windows=WINDOWS):
    return [f"{p}_{w}" for w in windows
            for p in ("src_n", "src_uports", "src_udst", "src_synr", "dst_usrc")]


# --------------------------------------------------------------------------
# Encoding categórico estável
# --------------------------------------------------------------------------
CAT_COLS = ["iface_in", "iface_out", "protocol", "chain"]


def fit_encoders(df, cols=CAT_COLS):
    """Vocabulário ordenado por coluna. Salve junto com o modelo (joblib)."""
    return {c: sorted(v for v in df.get_column(c).unique().to_list() if v is not None)
            for c in cols}


def _apply_encoders(df, encoders):
    return df.with_columns([
        pl.col(c).replace_strict({v: i for i, v in enumerate(vocab)},
                                 default=-1, return_dtype=pl.Int32).alias(f"{c}_e")
        for c, vocab in encoders.items()
    ])


# --------------------------------------------------------------------------
# Matriz de features
# --------------------------------------------------------------------------
def build_features(df, encoders=None, identity_features=False,
                   windows=WINDOWS, return_encoders=False, verbose=True):
    """Retorna (X float32, feature_names, df_pandas[, encoders]).

    encoders: None no treino (ajusta a partir de df); na inferência, passe o
              dicionário salvo no treino.
    identity_features: inclui octetos de IP e MAC. Desligado por padrão: faz o
              modelo aprender "quem" em vez de "como se comporta" e marcar
              qualquer host novo como anômalo.
    """
    log = print if verbose else (lambda *a, **k: None)
    log("  [polars] Engenharia de features...")

    if encoders is None:
        encoders = fit_encoders(df)

    # Temporais (fuso local)
    df = df.with_columns([
        (pl.col("dt").dt.hour() + pl.col("dt").dt.minute() / 60).alias("hour_f"),
        pl.col("dt").dt.weekday().alias("dow"),          # 1=seg ... 7=dom
    ]).with_columns([
        (2 * np.pi * pl.col("hour_f") / 24).sin().alias("hour_sin"),
        (2 * np.pi * pl.col("hour_f") / 24).cos().alias("hour_cos"),
        (pl.col("dow") >= 6).cast(pl.Int8).alias("weekend"),
    ])

    df = _apply_encoders(df, encoders)

    # Direção
    df = df.with_columns([
        pl.col("src_ip").str.contains(RE_PRIVATE).cast(pl.Int8).alias("src_priv"),
        pl.col("dst_ip").str.contains(RE_PRIVATE).cast(pl.Int8).alias("dst_priv"),
        (pl.col("chain") == "input").cast(pl.Int8).alias("to_router"),
        (pl.col("iface_in") != pl.col("iface_out")).cast(pl.Int8).alias("cross_vlan"),
    ]).with_columns(
        ((pl.col("src_priv") == 1) & (pl.col("dst_priv") == 1))
          .cast(pl.Int8).alias("lateral")
    )

    # Portas (porta de origem efêmera não entra: é ruído)
    df = df.with_columns([
        (pl.col("dst_port") > 0).cast(pl.Int8).alias("has_ports"),
        pl.col("dst_port").is_in(SUSPICIOUS_PORTS).cast(pl.Int8).alias("dst_susp"),
        ((pl.col("dst_port") > 0) & (pl.col("dst_port") < 1024))
          .cast(pl.Int8).alias("dst_wk"),
    ])

    # Flags TCP (só valem para TCP; ICMP usa o mesmo campo para type/code)
    is_tcp = pl.col("protocol") == "TCP"
    df = df.with_columns([
        (is_tcp & pl.col("flags_raw").str.contains(fl)).cast(pl.Int8).alias(f"f_{fl}")
        for fl in ("SYN", "ACK", "PSH", "FIN", "RST")
    ])
    if "syn_only" not in df.columns:
        df = df.with_columns(_syn_only_expr().alias("syn_only"))

    # Pacote
    df = df.with_columns([
        (pl.col("pkt_len").cast(pl.Float64) + 1).log().alias("pkt_log"),
        (pl.col("pkt_len") <= 60).cast(pl.Int8).alias("pkt_tiny"),
    ])

    # Janelas: só calcula se ainda não existem (amostra já vem com elas)
    wf = window_feature_names(windows)
    if not all(c in df.columns for c in wf):
        log("  [polars] AVISO: calculando janelas sobre este df. Se ele for "
            "uma amostra, as contagens ficam subestimadas.")
        df = add_window_features(df, windows)

    feats = (["hour_sin", "hour_cos", "dow", "weekend"]
             + [f"{c}_e" for c in encoders]
             + ["src_priv", "dst_priv", "lateral", "cross_vlan", "to_router",
                "has_ports", "dst_port", "dst_susp", "dst_wk",
                "f_SYN", "f_ACK", "f_PSH", "f_FIN", "f_RST", "syn_only",
                "pkt_len", "pkt_log", "pkt_tiny"]
             + wf)

    if identity_features:
        df = df.with_columns([
            pl.col(col).str.split(".").list.get(i).cast(pl.Int32, strict=False)
              .fill_null(0).alias(f"{p}o{i}")
            for p, col in (("s", "src_ip"), ("d", "dst_ip")) for i in range(4)
        ])
        df = df.with_columns(
            pl.col("src_mac").cast(pl.Categorical).to_physical().alias("src_mac_e"))
        feats += [f"{p}o{i}" for p in ("s", "d") for i in range(4)] + ["src_mac_e"]

    X = df.select(feats).fill_null(0).to_numpy().astype(np.float32)
    log(f"  [polars] Features: {len(feats)} | shape: {X.shape}")

    keep = ["ts", "dt", "hostname", "chain", "prefix", "src_ip", "dst_ip",
            "src_port", "dst_port", "protocol", "flags_raw", "pkt_len",
            "iface_in", "iface_out", "unidade", "direcao", "entre_unidades",
            "fw_flag", "is_atk", "atk_regime"]
    df_pd = df.select([c for c in keep if c in df.columns]).to_pandas()

    if return_encoders:
        return X, feats, df_pd, encoders
    return X, feats, df_pd



# --------------------------------------------------------------------------
# v3: unidade (secretaria) e direção do tráfego
# --------------------------------------------------------------------------
def add_unit_columns(df, unit_map=None, wan_ifaces=None):
    """Acrescenta:
      lado_interno   interface do lado da rede interna (define a unidade)
      unidade        secretaria dona do tráfego (UNIT_MAP; fallback: hostname)
      direcao        saida | entrada | interna | roteador | outro
      entre_unidades 1 se o tráfego interno cruza secretarias diferentes

    Regras:
      forward  interna->WAN : saida,    unidade = bridge de entrada
      forward  WAN->interna : entrada,  unidade = bridge de saída
      forward  interna->interna: interna, unidade = bridge de ORIGEM
      input    (destino = roteador): unidade = bridge de entrada; se vier da
               WAN, não há como atribuir a uma secretaria (o IP público é
               compartilhado) -> "<hostname> (roteador)"
      output   (origem = roteador): unidade = bridge de saída
    """
    unit_map = UNIT_MAP if unit_map is None else unit_map
    wan_ifaces = WAN_IFACES if wan_ifaces is None else wan_ifaces

    wan_keys = [f"{h}|{i}" for h, ifs in wan_ifaces.items() for i in ifs]
    specific = {f"{h}|{i}": u for (h, i), u in unit_map.items() if i != "*"}
    default = {h: u for (h, i), u in unit_map.items() if i == "*"}

    host = pl.col("hostname").fill_null("?")
    key_in = pl.concat_str([host, pl.lit("|"), pl.col("iface_in")])
    key_out = pl.concat_str([host, pl.lit("|"), pl.col("iface_out")])
    in_wan = key_in.is_in(wan_keys)
    out_wan = key_out.is_in(wan_keys)
    chain = pl.col("chain")

    def unit_of(key_expr):
        return (key_expr.replace_strict(specific, default=None, return_dtype=pl.Utf8)
                .fill_null(host.replace_strict(default, default=None,
                                               return_dtype=pl.Utf8))
                .fill_null(host))

    df = df.with_columns([
        pl.when(chain.is_in(["input", "output"])).then(pl.lit("roteador"))
          .when(~in_wan & out_wan).then(pl.lit("saida"))
          .when(in_wan & ~out_wan).then(pl.lit("entrada"))
          .when(~in_wan & ~out_wan).then(pl.lit("interna"))
          .otherwise(pl.lit("outro")).alias("direcao"),
        pl.when(chain == "output").then(pl.col("iface_out"))
          .when((chain == "input") & in_wan).then(None)
          .when(in_wan & ~out_wan).then(pl.col("iface_out"))
          .when(~in_wan).then(pl.col("iface_in"))
          .otherwise(None).alias("lado_interno"),
        (~in_wan & ~out_wan & (chain == "forward")
         & (unit_of(key_in) != unit_of(key_out))).cast(pl.Int8).alias("entre_unidades"),
    ])
    key_side = pl.concat_str([host, pl.lit("|"), pl.col("lado_interno")])
    df = df.with_columns(
        pl.when(pl.col("lado_interno").is_null())
          .then(pl.concat_str([host, pl.lit(" (roteador)")]))
          .otherwise(unit_of(key_side)).alias("unidade")
    )
    return df


# --------------------------------------------------------------------------
# v3: conversão para Parquet (processar o texto uma única vez)
# --------------------------------------------------------------------------
def export_to_parquet(paths, out_dir, dedup="tolerance", attack_windows=None,
                      windows=WINDOWS, unit_map=None, wan_ifaces=None,
                      dedup_tol_s=DEDUP_TOL_S):
    """Para cada arquivo de export (idealmente 1 por dia e por roteador):
    parse -> dedup -> unidade -> [ground truth] -> features de janela sobre o
    arquivo INTEIRO -> Parquet (zstd) em out_dir/<nome>.parquet.
    Retorna a lista de arquivos gerados.
    """
    if isinstance(paths, str):
        paths = [paths]
    os.makedirs(out_dir, exist_ok=True)
    outs = []
    for p in paths:
        df = load_and_parse(p, dedup=dedup, dedup_tol_s=dedup_tol_s)
        df = add_unit_columns(df, unit_map, wan_ifaces)
        if attack_windows is not None:
            df = label_ground_truth(df, attack_windows)
        df = add_window_features(df, windows, causal=True)
        stem = os.path.basename(p)
        for ext in (".gz", ".txt", ".log"):
            if stem.endswith(ext):
                stem = stem[: -len(ext)]
        out = os.path.join(out_dir, stem + ".parquet")
        df.write_parquet(out, compression="zstd", statistics=True)
        mb_in = os.path.getsize(p) / 1e6
        mb_out = os.path.getsize(out) / 1e6
        print(f"  [parquet] {os.path.basename(p)} ({mb_in:,.0f} MB) -> "
              f"{os.path.basename(out)} ({mb_out:,.0f} MB, {df.height:,} linhas)")
        outs.append(out)
    return outs


def scan_parquet(paths):
    """LazyFrame sobre um ou vários Parquet (aceita glob, ex. 'pq/*.parquet')."""
    return pl.scan_parquet(paths)


def descriptive_stats(paths, by=("dia", "unidade", "hora", "protocol")):
    """Total, média e desvio-padrão do VOLUME HORÁRIO para cada dimensão
    pedida. Base: contagem de registros por hora de calendário.
      dia      -> para cada dia: total do dia, média e dp entre suas horas
      hora     -> para cada hora do dia (0-23): total, média e dp entre dias
      unidade/protocol/... -> total e média/dp entre as horas da coleta
    Retorna {dimensão: DataFrame}.
    """
    lf = scan_parquet(paths).with_columns([
        pl.col("dt").dt.date().alias("dia"),
        pl.col("dt").dt.hour().alias("hora"),
        pl.col("dt").dt.truncate("1h").alias("_h"),
    ])
    res = {}
    for dim in by:
        if dim == "hora":
            base = lf.group_by(["dia", "hora"]).agg(pl.len().alias("n"))
            key = "hora"
        elif dim == "dia":
            base = lf.group_by(["dia", "_h"]).agg(pl.len().alias("n"))
            key = "dia"
        else:
            base = lf.group_by([dim, "_h"]).agg(pl.len().alias("n"))
            key = dim
        res[dim] = (base.group_by(key)
                        .agg([pl.col("n").sum().alias("total"),
                              pl.col("n").mean().round(1).alias("media_hora"),
                              pl.col("n").std().round(1).alias("dp_hora")])
                        .sort(key).collect())
    return res

# --------------------------------------------------------------------------
# v3: anonimização para tabelas e figuras do texto público
# --------------------------------------------------------------------------
def anonymize(df, unit_anon=None, host_anon=None, drop_identifiers=True):
    """Substitui nomes reais de secretarias e roteadores por rótulos
    anônimos em todas as colunas de texto (inclusive dentro de nomes de
    bridge, ex. 'bridgeXYZ' -> 'bridge<Secretaria B>'). Com
    drop_identifiers=True, remove IPs, MACs e prefixos de regra.
    Aceita DataFrame Polars ou pandas; devolve do mesmo tipo.
    """
    unit_anon = UNIT_ANON if unit_anon is None else unit_anon
    host_anon = HOST_ANON if host_anon is None else host_anon
    is_pd = not isinstance(df, pl.DataFrame)
    d = pl.from_pandas(df) if is_pd else df
    if drop_identifiers:
        d = d.drop([c for c in ("src_ip", "dst_ip", "src_mac", "prefix")
                    if c in d.columns])
    def sub(e, mapping, bracket):
        # nomes mais longos primeiro, para não substituir pedaços
        for real, fake in sorted(mapping.items(), key=lambda kv: -len(kv[0])):
            e = pl.when(e == real).then(pl.lit(fake)).otherwise(
                e.str.replace_all(real, f"<{fake}>" if bracket else fake,
                                  literal=True))
        return e

    str_cols = [c for c, t in zip(d.columns, d.dtypes) if t == pl.Utf8]
    exprs = []
    for c in str_cols:
        if c == "hostname":          # roteador -> "Roteador N"
            e = sub(pl.col(c), host_anon, bracket=False)
        elif c == "unidade":         # secretaria -> "Secretaria X"
            e = sub(sub(pl.col(c), unit_anon, False), host_anon, False)
        else:                        # dentro de nomes de interface etc.
            e = sub(sub(pl.col(c), unit_anon, True), host_anon, True)
        exprs.append(e.alias(c))
    d = d.with_columns(exprs)
    return d.to_pandas() if is_pd else d


# --------------------------------------------------------------------------
# Amostragem estratificada (por dia/arquivo)
# --------------------------------------------------------------------------
def _count_lines(path):
    opener = gzip.open if path.endswith(".gz") else open
    n = 0
    with opener(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 24), b""):
            n += chunk.count(b"\n")
    return n


def stratified_sample(paths, n_target=3_000_000, attack_windows=None,
                      windows=WINDOWS, seed=42, dedup="tolerance",
                      strata=("hostname", "unidade")):
    """Amostra estratificada por (arquivo/dia, hostname, unidade).

    Aceita:
      * arquivos .parquet gerados por export_to_parquet (recomendado): já
        vêm com dedup, unidade e janelas calculadas sobre o dia inteiro;
      * arquivos de texto do export (processa como na v2).

    Preserva todas as linhas com fw_flag=1 ou is_atk=1 (para o TESTE).
    Na hora de treinar, filtre: fw_flag == 0 e is_atk == 0.
    """
    if isinstance(paths, str):
        paths = [paths]
    is_pq = [p.endswith(".parquet") for p in paths]

    totals = {}
    for p, pq in zip(paths, is_pq):
        totals[p] = (pl.scan_parquet(p).select(pl.len()).collect().item()
                     if pq else _count_lines(p))
    grand = sum(totals.values())
    frac = min(n_target / grand, 1.0) if grand else 1.0
    print(f"  [polars] Total: {grand:,} linhas | fração: {frac:.4f}")

    parts = []
    for p, pq in zip(paths, is_pq):
        if pq:
            df = pl.read_parquet(p)
            if attack_windows is not None:
                df = label_ground_truth(df, attack_windows)
        else:
            df = load_and_parse(p, dedup=dedup)
            df = add_unit_columns(df)
            if attack_windows is not None:
                df = label_ground_truth(df, attack_windows)
            df = add_window_features(df, windows)

        st = [c for c in strata if c in df.columns] or ["iface_in"]
        keep = (pl.col("fw_flag") == 1) | (pl.col("is_atk") == 1)
        normal = (
            df.filter(~keep)
              .with_columns(pl.int_range(pl.len()).shuffle(seed=seed)
                              .over(st).alias("_r"))
              .filter(pl.col("_r") < (pl.len().over(st) * frac).ceil())
              .drop("_r")
        )
        special = df.filter(keep)
        parts.append(pl.concat([normal, special], how="vertical_relaxed"))
        print(f"      {os.path.basename(p)}: {normal.height:,} normais + "
              f"{special.height:,} preservadas")

    out = pl.concat(parts, how="diagonal_relaxed")
    print(f"  [polars] Amostra final: {out.height:,} linhas")
    return out


# --------------------------------------------------------------------------
# Diagnóstico
# --------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 500_000
    d = load_and_parse(sys.argv[1], max_lines=n)
    print("\nCobertura por chain x protocolo:")
    print(d.group_by(["chain", "protocol"]).len().sort("len", descending=True))
    d = add_unit_columns(d)
    print("\nRegistros por hostname x unidade x direção:")
    print(d.group_by(["hostname", "unidade", "direcao"]).len()
           .sort(["hostname", "len"], descending=[False, True]))
    print("\nInterfaces internas sem regra específica em UNIT_MAP (caem no padrão "
          "do roteador; revise):")
    specific = {(h, i) for (h, i) in UNIT_MAP if i != "*"}
    has_default = {h for (h, i) in UNIT_MAP if i == "*"}
    sem = (d.filter(pl.col("lado_interno").is_not_null())
            .group_by(["hostname", "lado_interno"]).len()
            .filter(pl.struct(["hostname", "lado_interno"]).map_elements(
                lambda r: (r["hostname"], r["lado_interno"]) not in specific
                and r["hostname"] not in has_default, return_dtype=pl.Boolean))
            .sort("len", descending=True))
    print(sem)
    print("\nLinhas com detecção do firewall por prefixo:")
    print(d.filter(pl.col("fw_flag") == 1).group_by("prefix").len())
    X, feats, _ = build_features(d)
    print("\nOK:", X.shape, "features:", len(feats))
