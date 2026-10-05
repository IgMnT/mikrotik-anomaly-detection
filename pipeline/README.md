# Pipeline de detecção de anomalias — treino, testes e varredura em tempo real

## Arquivos

| Arquivo | Função |
|---|---|
| `exportar_loki.py` | Export do Loki: 1 arquivo por roteador por dia (meia-noite local), download paralelo, conferência com `count_over_time` |
| `common_features_polars.py` | Parsing, dedup, unidade (secretaria), features de janela causais, `WindowState`, Parquet, estatística descritiva, anonimização |
| `models.py` | 5 detectores com a mesma interface; GPU quando disponível, CPU como alternativa |
| `train.py` | Treino e avaliação (item 5.2) → `bundle.joblib` + CSVs de métricas |
| `inference.py` | Motor de inferência compartilhado pelo teste e pelo scanner |
| `test_inference.py` | Testes T1–T6 do modo de inferência (item 5.5) |
| `realtime_scanner.py` | Varredura em tempo quase real sobre o Loki, alertas e publicação no Grafana |
| `gerar_cenarios.py` | Monta o `cenarios.json` lendo as bridges reais de cada secretaria: 5 cenários forward por secretaria, com ritmos, horários e dias variados |
| `injetor_sintetico.py` | Injeta ataques sintéticos (abaixo do limiar) nos exports reais, imitando o tráfego de fundo, e registra no `ataques.csv` |
| `cenarios_exemplo.json` | Modelo dos cenários de injeção |
| `analise_unidades.py` | Anomalias por secretaria: taxa por 10 mil registros com IC 95%, direção, hora, portas e fração "só ML" (T18) |
| `empacotar_saidas.py` | Junta todas as saídas, varre IPs/MACs/nomes e gera um zip seguro para envio |
| `rodar_tudo.sh` | Roda o pipeline inteiro em sequência e termina no zip |
| `ataques_template.csv` | Modelo do arquivo de ground truth (com `dst_ip` = alvo) |
| `testes/gera_sim.py`, `testes/fake_loki.py` | Dados sintéticos e Loki falso, para testar sem os dados reais |

Dependências: `pip install polars numpy scikit-learn joblib requests pyarrow pandas matplotlib`.
Para GPU (no WSL2): RAPIDS **cuML ≥ 26.08** (é a versão com Isolation Forest) e CuPy.
Opcional: `thundersvm` para o One-Class SVM em GPU.

## Rodada completa (um comando)

Depois de preparar `export/`, os mapas de unidade, `ataques.csv` e (opcional) `cenarios.json`:

```bash
DEDUP_TOL=0.001 LIMIAR_PORTAS=<N> LIMIAR_JANELA=<S> bash rodar_tudo.sh
```

O script injeta os cenários, gera os Parquet, treina, testa, faz o replay de cada dia com
ataque, analisa por secretaria e termina em `saidas_tcc_<data>.zip`, já sanitizado. Preencha o
`respostas.md` que ele cria e rode só o `empacotar_saidas.py` de novo. **Envie apenas esse zip**,
nunca os exports, os Parquet ou o `bundle.joblib`: eles contêm IPs e MACs.

## Passo a passo

```bash
# 0. Configure UNIT_MAP / WAN_IFACES / UNIT_ANON / HOST_ANON no topo de
#    common_features_polars.py (hostnames reais, bridges, interfaces WAN)

# 1. Export do Loki: 1 arquivo por roteador por dia, com hostname
#    (formato <ts_ns>\t<hostname>\t<linha> ou nome HOSTNAME_AAAA-MM-DD.txt)

# 2. Escolher a tolerância da dedup pelo histograma (cópias do syslog x repetições legítimas)
python -c "import common_features_polars as cf; cf.diagnose_duplicates('export/ROTEADOR_1_2026-09-17.txt')"

# 2b. Injetar os ataques sintéticos (limiares só no comando, nunca no texto)
python injetor_sintetico.py --export "export/*.txt" --cenarios cenarios.json \
       --out export_injetado --ataques ataques.csv --limiar-portas <N> --limiar-janela-s <S>

# 3. Parquet (parse + dedup + unidade + janelas causais + ground truth), uma vez
python -c "
import glob, common_features_polars as cf
aw = cf.read_attack_windows('ataques.csv')
cf.export_to_parquet(sorted(glob.glob('export_injetado/*.txt')), 'pq', dedup='tolerance', dedup_tol_s=0.001, attack_windows=aw)"

# 4. Estatística descritiva (pedido do orientador), já anonimizada
python -c "
import common_features_polars as cf
for k, t in cf.descriptive_stats('pq/*.parquet').items(): print(k); print(cf.anonymize(t))"

# 5. Treino e avaliação
python train.py --parquet "pq/*.parquet" --ataques ataques.csv --out modelos

# 6. Testes de inferência
python test_inference.py --bundle modelos/bundle.joblib --export export/ROTEADOR_1_2026-09-18.txt

# 7a. Demonstração com dados gravados (item 5.5), medindo latência de detecção
python realtime_scanner.py --bundle modelos/bundle.joblib \
       --replay "export/*_2026-09-18.txt" --velocidade 60 --ataques ataques.csv

# 7b. Tempo real sobre o Loki, publicando os alertas no Grafana
python realtime_scanner.py --bundle modelos/bundle.joblib \
       --loki http://localhost:3100 --push-loki
```

No Grafana, os alertas ficam em `{job="ml-anomaly"}`, com labels `unidade` e `severidade`.
O detalhe de cada alerta (origem, portas, destinos, votos, modelos) vai no corpo JSON:
`{job="ml-anomaly"} | json | so_ml="true"` mostra só o que o firewall não pegou.

## Saídas do treino (`modelos/`)

| Arquivo | Uso no cap. 5 |
|---|---|
| `metricas_resumo.csv` | Tabela de comparação dos algoritmos (média entre sementes, F1 ± dp, alertas/dia, tempos) |
| `deteccao_por_regime.csv` | **Tabela central**: recall por evento do modelo × do firewall, por regime (acima/abaixo) e origem (real/sintético) |
| `deteccao_por_evento.csv` | Detecção evento a evento |
| `metricas_por_semente.csv` | Dados brutos para o desvio-padrão |
| `bundle.joblib` | Modelos, scaler, encoders, limiares e conjunto de verificação |

## Decisões de projeto (entram na metodologia)

1. **Janelas causais.** Cada registro recebe as contagens acumuladas *até ele* na janela corrente
   (5 min, 1 h, 24 h), e não o total da janela. É o que existe em tempo real; treinar com o total
   criaria divergência entre treino e serviço. O teste T2 verifica que o cálculo offline (treino)
   e o incremental (scanner) são idênticos.
2. **Limiar sem olhar o teste.** Percentil `q` (padrão 99,5) dos escores no treino; no DBSCAN, o
   próprio `eps`, estimado pelo percentil das distâncias ao k-ésimo vizinho.
3. **Ground truth por janela + IP**, nunca pelo prefixo das regras do firewall (seria circular).
4. **Registros pós-ataque excluídos.** Depois de um ataque, a janela de 24 h da origem continua
   alta até a meia-noite. Esses registros não são ataque nem tráfego normal limpo: ficam fora do
   treino (ensinariam que contagens altas são normais) e do teste (inflariam os falsos positivos).
5. **Recall por evento e por registro**, precisão tratada como limite inferior, alertas/dia.
6. **Espera por origem no scanner** (padrão 60 min): o mesmo efeito do item 4 gera alertas
   repetidos da mesma origem; ela só volta a alertar se o comportamento escalar.

## Tempo real: como funciona

- A cada `--intervalo` (15 s), consulta o Loki desde o último cursor, até agora menos o atraso de
  ingestão (5 s), em páginas de 5.000 linhas.
- Ignora `http_proxy` do ambiente (mesmo problema já resolvido no Promtail).
- **Aquecimento**: `hora` (padrão) reprocessa desde o início da hora; `dia`, desde a meia-noite
  (exato para a janela de 24 h, porém mais lento na partida).
- Alertas agregados por (roteador, secretaria, origem, 5 min), com severidade pelos votos
  (3 = baixa, 4 = média, 5 = alta) e marcação **só ML** quando o firewall não sinalizou nada.
- Labels do Loki apenas de baixa cardinalidade; IP e porta vão no texto do alerta.

**Latência de detecção** = latência nos dados (reportada no replay) + intervalo de consulta +
atraso de ingestão. Com os padrões, cerca de 20 s depois do primeiro registro anômalo.

## Resultados com dados sintéticos (validação do código, não do modelo)

- T1 integridade do bundle: diferença 0
- T2 janelas offline × incrementais: diferença 0 (1.440 lotes de 60 s)
- T3 dedup em lotes × de uma vez: idênticas
- T4 LOF manual (caminho GPU) × sklearn: correlação 1,000000
- T6 hora de pico processada usando 0,4% do intervalo entre lotes (CPU)
- Paginação do Loki: sem perdas nem duplicatas (páginas de 97 linhas)
- Replay: 3 de 3 ataques detectados, os 2 abaixo do limiar marcados como "só ML"

## Dedup (mudou em 23/09)

A regra antiga (conteúdo idêntico no mesmo intervalo de 1 s) apagava tráfego legítimo, porque
ACKs de uma mesma conexão geram linhas idênticas. A regra atual remove uma linha só quando a
linha idêntica **anterior** do mesmo roteador chegou há menos de `DEDUP_TOL_S` (padrão 1 ms).
Escolha o valor pelo histograma de `diagnose_duplicates()` e use o mesmo em `export_to_parquet`,
`test_inference.py --dedup-tol` e `realtime_scanner.py --dedup-tol`.

## Ground truth

`ataques.csv`: `start,end,src_ip,dst_ip,regime,origem,tipo[,gerador]`. Preencha `dst_ip` (o alvo)
sempre que a máquina de ataque também gerar tráfego normal; sem ele, todo o tráfego da origem
na janela vira "ataque". O injetor acrescenta suas linhas com `gerador=injetor` e, ao ser
reexecutado, substitui só essas.

## Cuidados

- **Re-exporte os Parquet com esta versão** antes de treinar: os Parquet antigos têm janelas não causais.
- T5 (vocabulário): bridge ou secretaria nova vira código -1. Se for tráfego normal, atualize
  `UNIT_MAP` e retreine.
- Tudo que for para o texto do TCC passa por `cf.anonymize()`, e prints do Grafana devem ser
  recortados ou borrados (hostnames, IPs, MACs, bridges).
- O estado do scanner fica em memória; se o processo reiniciar, use `--aquecimento dia` para
  reconstruir exatamente a janela de 24 h.
