#!/usr/bin/env bash
# =============================================================================
# rodar_tudo.sh — pipeline completo, do export ao zip para envio
# =============================================================================
# Antes de rodar (quinta-feira):
#   1. export/ com um arquivo por roteador e por dia (corte à meia-noite local)
#   2. UNIT_MAP / WAN_IFACES / UNIT_ANON / HOST_ANON configurados em
#      common_features_polars.py
#   3. tolerância da dedup escolhida pelo histograma (variável DEDUP_TOL)
#   4. ataques.csv com os ataques reais (com dst_ip)
#   5. cenarios.json com os cenários de injeção (opcional; sem ele, pula a injeção)
#
# Uso:   DEDUP_TOL=0.001 LIMIAR_PORTAS=<N> LIMIAR_JANELA=<S> bash rodar_tudo.sh
# Tudo é registrado em rodada.log. Se alguma etapa falhar, o script para.
# =============================================================================
set -euo pipefail
DEDUP_TOL="${DEDUP_TOL:-0}"   # 0 = sem dedup (decidido em 24/09 pelo teste dos SYN)
EXPORT="${EXPORT:-export}"
SEEDS="${SEEDS:-3}"                       # sementes dos modelos aleatórios
MAX_FIT_LOF="${MAX_FIT_LOF:-200000}"      # pontos de ajuste do LOF (CPU: 200 mil)
MAX_FIT_DBSCAN="${MAX_FIT_DBSCAN:-100000}"
N_SAMPLE="${N_SAMPLE:-3000000}"
MAX_LOTES_T6="${MAX_LOTES_T6:-40}"        # lotes do teste de capacidade
DEVICE="${DEVICE:-auto}"
exec > >(tee -a rodada.log) 2>&1
echo "=== rodada iniciada em $(date '+%d/%m/%Y %H:%M') | dedup ${DEDUP_TOL}s | sementes ${SEEDS} | LOF ${MAX_FIT_LOF} | DBSCAN ${MAX_FIT_DBSCAN} ==="

# 1. injeção dos ataques sintéticos (os exports originais não são alterados)
if [[ -f cenarios.json ]]; then
  echo "--- [1/7] injeção de ataques sintéticos"
  EXTRA=()
  [[ -n "${LIMIAR_PORTAS:-}" ]] && EXTRA+=(--limiar-portas "$LIMIAR_PORTAS" --limiar-janela-s "${LIMIAR_JANELA:-3}")
  python injetor_sintetico.py --export "${EXPORT}/*" --cenarios cenarios.json \
         --out export_injetado --ataques ataques.csv --dedup-tol "$DEDUP_TOL" ${EXTRA[@]+"${EXTRA[@]}"}
  SRC=export_injetado
else
  echo "--- [1/7] sem cenarios.json: injeção pulada"
  SRC="$EXPORT"
fi

# 2. Parquet (parse, dedup, secretaria, janelas causais, ground truth)
echo "--- [2/7] Parquet"
python - <<EOF
import glob, common_features_polars as cf
aw = cf.read_attack_windows("ataques.csv")
cf.export_to_parquet(sorted(glob.glob("${SRC}/*")), "pq", attack_windows=aw,
                     dedup_tol_s=${DEDUP_TOL})
EOF

# 3. treino e avaliação
echo "--- [3/7] treino"
python train.py --parquet "pq/*.parquet" --ataques ataques.csv --out modelos \
       --seeds "$SEEDS" --device "$DEVICE" --n-sample "$N_SAMPLE" \
       --max-fit-lof "$MAX_FIT_LOF" --max-fit-dbscan "$MAX_FIT_DBSCAN"

# 4. testes de inferência (dia de maior volume)
DIA_TESTE=$(ls -S ${SRC}/* | head -1)
echo "--- [4/7] testes de inferência em $(basename "$DIA_TESTE")"
python test_inference.py --bundle modelos/bundle.joblib --export "$DIA_TESTE" \
       --dedup-tol "$DEDUP_TOL" --max-lotes "$MAX_LOTES_T6" || echo "(há testes reprovados; veja relatorio_inferencia.json)"

# 5. replay de cada dia que tem ataque rotulado (latência e alertas por dia)
echo "--- [5/7] replay"
for DIA in $(python -c "
import polars as pl
a = pl.read_csv('ataques.csv', try_parse_dates=True)
print(' '.join(sorted({str(d)[:10] for d in a['start']})))"); do
  echo "    dia $DIA"
  python realtime_scanner.py --bundle modelos/bundle.joblib --replay "${SRC}/*_${DIA}*" \
         --intervalo 60 --velocidade 0 --ataques ataques.csv --dedup-tol "$DEDUP_TOL" \
         --saida "replay_${DIA}.jsonl" --quieto
done

# 6. análise por secretaria
echo "--- [6/7] análise por secretaria"
python analise_unidades.py --bundle modelos/bundle.joblib --parquet "pq/*.parquet" \
       --ataques ataques.csv --out analise

# 7. pacote seguro para envio
echo "--- [7/7] empacotamento"
python empacotar_saidas.py --parquet "pq/*.parquet" --export "${EXPORT}/*" --replay "replay_*_resumo.json"
echo "=== rodada concluída em $(date '+%d/%m/%Y %H:%M') ==="
echo "Confira o LEIA-ME.md e os PNGs dentro do zip antes de enviar."
