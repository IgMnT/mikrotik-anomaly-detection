# Projeto TCC — Análise de Logs de Rede MikroTik com Machine Learning

Inventário completo do conteúdo da pasta `TCC/`: propósito, arquivos, serviços,
versões e fluxo de dados. Gerado a partir da inspeção direta dos arquivos do
projeto em 2026-09-29.

## Visão geral

O projeto monta um pipeline de observabilidade para coletar logs de firewall/
syslog de um roteador **MikroTik RouterOS 6.49**, armazená-los no **Grafana
Loki** e visualizá-los no **Grafana**, com o objetivo de gerar um dataset de
tráfego normal + tráfego de ataque (via um laboratório de ataques em
container) para treinar modelos de ML. Não há, nesta pasta, código de
treinamento de ML ainda — apenas a infraestrutura de coleta/armazenamento de
logs e os artefatos de laboratório de ataque.

Ambiente do host: **Windows 11 Pro** com **Docker Desktop + WSL2 (Ubuntu)**.

## Estrutura de diretórios

```
TCC/
├── PROMTAIL_STATUS.md            # status/log de implementação do Promtail
├── sample_logs.json            # dump de uma query ao Loki (1,1 MB, 1 linha)
├── Observability/                # stack de observabilidade (Docker Compose)
│   ├── docker-compose.yml
│   ├── mikrotik-syslog.rsc       # script RouterOS (Winbox) p/ exportar syslog
│   ├── Loki/
│   │   └── loki-config.yaml
│   ├── Otel/
│   │   └── otel-config.yaml
│   └── Grafana/
│       ├── dashboards/
│       │   └── mikrotik-security.json
│       └── provisioning/
│           ├── dashboards/dashboards.yaml
│           └── datasources/loki.yaml
└── docker-lab/                   # container de simulação de ataques
    ├── Dockerfile
    ├── docker-compose.yml
    └── attack_simulator.sh
```

## Serviços e versões (stack `Observability/docker-compose.yml`)

| Serviço | Imagem | Versão | Portas host | Função |
|---|---|---|---|---|
| `otel-collector` | `otel/opentelemetry-collector-contrib` | `latest` | `1514/tcp`, `4317`, `4318`, `8888` | Recebe syslog do MikroTik (TCP), faz parsing e encaminha para o Loki via OTLP/HTTP |
| `loki` | `grafana/loki` | **3.3.2** | `3100` | Armazenamento dos logs (backend TSDB, filesystem) |
| `grafana` | `grafana/grafana` | **11.4.0** | `3001` (mapeada para 3000 interno) | Visualização e dashboards (credenciais padrão `admin`/`admin`, sign-up desabilitado) |

Rede: `observability` (driver `bridge`). Volumes nomeados: `loki-data`,
`grafana-data`.

> Nota histórica (ver `PROMTAIL_STATUS.md`): o mapeamento `1514:1514/udp` foi
> removido do `otel-collector` porque o Docker Desktop/WSL2 não entrega
> pacotes UDP a containers — hoje o `otel-collector` só recebe syslog via
> **TCP** na porta 1514. O tráfego **UDP** do MikroTik é tratado por um
> **Promtail nativo rodando no WSL2** (fora do Docker), não presente nesta
> pasta como configuração versionada (config vive em `~/promtail-config.yaml`
> dentro do WSL).

### Promtail (WSL2, fora do Docker Compose)

| Item | Valor |
|---|---|
| Versão | **3.3.2** (`promtail-linux-amd64`, mesma versão do release do Loki) |
| Instalação | binário nativo em `/usr/local/bin/promtail` dentro da distro WSL `Ubuntu` |
| Execução | serviço `systemd` (`/etc/systemd/system/promtail.service`), usuário `youruser` |
| Escuta | `0.0.0.0:1514` (UDP, `syslog_format: rfc3164`) |
| Destino | `http://localhost:3100/loki/api/v1/push` |
| Motivo de existir | RouterOS 6.49 só envia syslog por UDP; Docker Desktop não entrega UDP a containers; solução foi rodar o Promtail nativamente no WSL2 (onde UDP funciona) |

## Detalhes de configuração

### `Observability/Loki/loki-config.yaml`
- `auth_enabled: false`
- HTTP `3100` / gRPC `9096`
- Storage: filesystem local (`schema v13`, `tsdb`, a partir de `2020-10-24`)
- Retenção: `reject_old_samples_max_age: 168h` (7 dias), `table_manager.retention_period: 720h` (30 dias), compactor com `retention_enabled: true`
- Limites: `ingestion_rate_mb: 16`, `ingestion_burst_size_mb: 32`, `per_stream_rate_limit: 5MB`
- `analytics.reporting_enabled: false`

### `Observability/Otel/otel-config.yaml`
- **Receiver** `syslog` em UDP e TCP `1514`, protocolo `rfc3164`, com operadores de parsing (`regex_parser`) para três formatos de log do MikroTik:
  - `access forward:` (tráfego de firewall — extrai `iface_in`, `iface_out`, `src_mac`, `protocol`, `tcp_flags`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `pkt_len`)
  - prefixos de ataque de laboratório (`[LAB-*]`, `_atk`, `[PORT-SCAN]`, `[SYN-FLOOD]`, `[SSH-BLACKLIST]`, `[WINBOX-BRUTE]`)
  - eventos de autenticação (`logged in`/`logged out`/`login failure`)
  - adiciona atributos fixos `source=mikrotik`, `collector=otel`
- **Processors**: `batch` (2s / 500), `resource` (define `service.name=mikrotik-firewall`, `host.name=mikrotik-lab`)
- **Exporters**: `otlphttp` → `http://loki:3100/otlp` (TLS insecure), `debug` (verbosity detailed)
- **Extensions**: `health_check` em `0.0.0.0:13133`

### `Observability/Grafana/provisioning/`
- Datasource único: **Loki** (`http://loki:3100`), marcado como default
- Dashboard provisionado a partir de arquivo (`/var/lib/grafana/dashboards`), pasta `MikroTik`

### `Observability/Grafana/dashboards/mikrotik-security.json`
Dashboard "**MikroTik — Security Monitor (TCC)**" com 6 painéis, todos sobre o datasource Loki:
1. Logs por Segundo (timeseries)
2. Logs de Ataque por Segundo (timeseries — filtros `LAB-` e `_atk`)
3. Logs de Ataque (Stream) — filtro `LAB-|_atk|PORT-SCAN|SYN-FLOOD|BRUTE|BLACKLIST`
4. Top IPs de Origem (Ataques) — `topk(10, ...)` por `src_ip`
5. Distribuição por Protocolo
6. Todos os Logs (Stream)

### `Observability/mikrotik-syslog.rsc`
Script RouterOS (colável no terminal Winbox) que:
- Cria uma ação de log `remote_otel` (`bsd-syslog=yes`, `syslog-facility=local0`) apontando para `COLLECTOR_HOST:1514`
- Associa os tópicos `firewall`, `dhcp`, `dns`, `system`, `wireless`, `critical`, `error`, `warning`, `info` a essa ação

## Laboratório de ataques (`docker-lab/`)

### `Dockerfile`
- Base: **`ubuntu:22.04`**
- Ferramentas instaladas via `apt`: `nmap`, `hping3`, `hydra`, `dnsutils`, `netcat-openbsd`, `iputils-ping`, `curl`, `wget`, `net-tools`, `iproute2`, `arping`, `tcpdump`, `python3`, `python3-pip`
- Pacote Python: `requests` (via `pip3 install --break-system-packages`)
- Copia e dá permissão de execução a `attack_simulator.sh`
- `CMD ["bash"]` (container interativo)

### `docker-compose.yml`
- Serviço `atacante` (container `lab-atacante-tcc`)
- `network_mode: host`, `privileged: true` (necessário para raw sockets do `hping3`)
- `stdin_open`/`tty` ativos (modo interativo)
- Volumes: `./logs:/lab/logs`, `./attack_simulator.sh:/lab/attack_simulator.sh`

### `attack_simulator.sh`
Script Bash (`set -euo pipefail`) para gerar tráfego malicioso real contra um
alvo MikroTik **próprio**, em laboratório controlado (o script exibe aviso
legal citando o Art. 154-A do Código Penal e pede confirmação interativa
antes de rodar). Ataques implementados:

| Ataque | Ferramenta | O que gera |
|---|---|---|
| `port-scan` | `nmap` (SYN, UDP, version/OS fingerprint, Xmas, NULL) | logs de drop no firewall |
| `brute-force` | `hydra` (SSH, HTTP WebFig, FTP, Telnet) + tentativas TCP na porta Winbox 8291 | logs de falha de autenticação |
| `syn-flood` | `hping3 --flood -S` em portas 80/443/8080/8291/22/53 | logs de limite de conexão/drop |
| `udp-flood` | `hping3 --udp --flood` (DNS 53, SNMP 161, portas aleatórias) | drops de UDP |
| `icmp-flood` | `hping3 --icmp --flood` + `ping -f -s 65500` | drops de ICMP / fragmentação |
| `dns-amplification` | `dig` em loop contra múltiplos domínios/tipos de registro | volume de queries DNS |
| `connection-flood` | `/dev/tcp` em loop contra várias portas | exaustão de tabela de conexões |
| `arp-spoof` | `arping` (fallback `hping3 --arp`) | tráfego ARP anômalo |
| `slowloris` | conexões HTTP incompletas via `/dev/tcp` | conexões lentas/penduradas |
| `normal` | `curl`, `dig`, `ping` | tráfego legítimo (baseline) |
| `all` | executa todos em sequência, com tráfego normal no início e no fim | dataset balanceado |

Uso: `sudo ./attack_simulator.sh --target <IP> --attack <tipo> --duration <seg>`.

## Arquivo de dados (`sample_logs.json`)

- 1,1 MB, JSON em uma única linha.
- É a resposta bruta da API do Loki `GET /loki/api/v1/query_range`
  (`"status":"success"`, `"resultType":"streams"`).
- Contém um stream com labels `{detected_level, host=mikrotik-lab,
  hostname=LAB, job=mikrotik-firewall, service_name=mikrotik-firewall,
  severity}` e uma lista de `[timestamp_ns, linha_de_log]`, no formato
  `access forward: in:<iface> out:<iface>, src-mac <mac>, proto <proto>,
  <ip>:<porta>-><ip>:<porta>, len <bytes>`.
- Inclui o bloco `stats` completo retornado pelo Loki (tempo de execução,
  bytes processados, chunks, cache, etc.) — útil para auditoria de
  performance da query, não para o dataset de ML em si.

## Documentação de processo (`PROMTAIL_STATUS.md`)

- **`PROMTAIL_STATUS.md`**: registro do que foi de fato implementado e
  validado:
  - Promtail 3.3.2 nativo no WSL2, serviço systemd ativo, `User=youruser`
  - Correção necessária: `syslog_format: rfc3164` (RouterOS manda BSD
    syslog/RFC3164, não RFC5424)
  - `NO_PROXY=localhost,127.0.0.1,::1` no serviço, por causa de um proxy
    corporativo (`proxy.example.com:80`) que interceptava o push HTTP
    do Promtail para o Loki
  - Removido o mapeamento `1514:1514/udp` do `otel-collector` no Docker
    Compose (a porta ficava reservada a nível de VM WSL2 e bloqueava o
    Promtail nativo)
  - `C:\Users\youruser\.wslconfig` alterado para `networkingMode=mirrored`
    e `hostAddressLoopback=true`, fazendo o WSL2 usar o IP real da LAN do
    Windows (`COLLECTOR_HOST`) em vez de NAT interno — elimina a necessidade de
    port-forward manual (que não suporta UDP no Windows)
  - Validado ponta-a-ponta com log de teste simulado via `nc -u`; **falta**
    apenas o teste com o MikroTik real enviando tráfego de produção

## Resumo de versões

| Componente | Versão |
|---|---|
| RouterOS (MikroTik) | 6.49 |
| Grafana Loki (container + Promtail) | 3.3.2 |
| Grafana | 11.4.0 |
| OpenTelemetry Collector Contrib | `latest` (sem tag fixa) |
| Ubuntu (base do lab de ataque) | 22.04 |
| Sistema operacional host | Windows 11 Pro (build 10.0.22621) |
| WSL2 | distro `Ubuntu`, modo de rede `mirrored` |

## Observações

- Não há um repositório Git inicializado nesta pasta (`TCC/`) — o histórico
  de mudanças vive apenas nos dois arquivos `.md` de status manual.
- Não há, nesta pasta, notebooks, scripts de pré-processamento ou modelos de
  Machine Learning — a etapa de ML ainda não foi iniciada; o que existe é a
  infraestrutura de coleta (`Observability/`) e geração de dados rotulados
  de ataque (`docker-lab/`).
- A imagem `otel/opentelemetry-collector-contrib:latest` não está fixada em
  uma versão — para reprodutibilidade do TCC, considerar fixar uma tag
  específica.
