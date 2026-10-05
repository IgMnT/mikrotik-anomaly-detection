# Status: Pipeline MikroTik → Promtail → Loki

Resumo do que foi implementado e validado no pipeline de coleta via Promtail.

## Status: implementado e validado ponta-a-ponta (falta só o teste real no MikroTik)

## O que foi feito

1. **Promtail 3.3.2** instalado nativo no WSL2 (distro `Ubuntu`), em
   `/usr/local/bin/promtail`.
2. **Config** em `~/promtail-config.yaml` (dentro do WSL, usuário `youruser`) —
   igual ao parser do `.md` original, **mais um campo necessário**:
   ```yaml
   syslog:
     ...
     syslog_format: rfc3164
   ```
   Sem isso o Promtail rejeita os logs do MikroTik com
   `expecting a version value in the range 1-999` — o Promtail espera RFC5424
   por padrão, e o RouterOS manda RFC3164 (BSD syslog).
3. **Serviço systemd** `/etc/systemd/system/promtail.service`, habilitado e
   ativo (`systemctl status promtail`). Roda como `User=youruser`, com:
   ```
   Environment=NO_PROXY=localhost,127.0.0.1,::1
   Environment=no_proxy=localhost,127.0.0.1,::1
   ```
   Necessário porque o WSL tem um **proxy corporativo** configurado
   (`http_proxy=http://proxy.example.com:80`) que, sem o `NO_PROXY`,
   tenta rotear o push HTTP do Promtail pro Loki através do proxy e falha
   (a rede intercepta com uma página do "Aker Firewall").
4. **Docker Compose** (`Observability/docker-compose.yml`): removido o
   mapeamento `"1514:1514/udp"` do serviço `otel-collector` (mantido só o
   TCP). Esse mapeamento UDP nunca funcionou (bug conhecido do Docker
   Desktop/WSL2 com UDP) mas ainda reservava a porta 1514/UDP a nível de VM
   WSL2 — como todas as distros WSL compartilham a mesma VM/rede, isso
   bloqueava o Promtail de bindar na mesma porta.
5. **Rede WSL2 mudada para "mirrored"** — arquivo `C:\Users\youruser\.wslconfig`:
   ```ini
   [wsl2]
   networkingMode=mirrored

   [experimental]
   hostAddressLoopback=true
   ```
   Efeito: o WSL2 passou a usar a **IP real da LAN do Windows**
   (`COLLECTOR_HOST`) em vez de uma IP interna NAT (`172.26.29.3`). Isso resolve
   o problema de roteamento sem precisar de port-forward manual (que não
   suporta UDP no Windows) — **o MikroTik já está configurado para apontar
   pra `COLLECTOR_HOST`, então nenhuma mudança é necessária na config dele.**
   Requereu `wsl --shutdown` + Docker Desktop reiniciar (ambos já
   confirmados de volta no ar: containers `loki`, `grafana`,
   `otel-collector` rodando; serviço `promtail` ativo).

## Validado

- Envio de log de teste simulado via `nc -u` para `COLLECTOR_HOST:1514`
  (o mesmo IP/porta que o MikroTik real usa) chegou no Loki com todos os
  labels do parser extraídos corretamente (`src_ip`, `dst_ip`, `dst_port`,
  `protocol`, `tcp_flags`, `iface_in`, `iface_out`, `hostname`, etc).

## Falta fazer: testar com o MikroTik de verdade

A ação de syslog já existe no `Observability/mikrotik-syslog.rsc`, apontando
para `COLLECTOR_HOST:1514` — **não precisa editar nada nela**, já está com o IP
certo (o script até já tinha esse IP antes de qualquer mudança, foi
coincidência boa: era o IP do Windows, que agora também é o IP do WSL).

No terminal do MikroTik (Winbox ou SSH):

```
# Confirma que a ação remote_otel existe e aponta pro IP/porta certos
/system logging action print detail where name=remote_otel

# Gera um log de teste manual
/log warning "TESTE_MIKROTIK_REAL - validando pipeline promtail"

# Ou gera tráfego real que bate numa regra de firewall com log=yes
/ip firewall filter print where log=yes
```

Para confirmar do lado do Windows que o log chegou no Loki:

```bash
curl -s -G "http://localhost:3100/loki/api/v1/query_range" \
  --data-urlencode 'query={job="mikrotik-firewall"}' \
  --data-urlencode "start=$(date -d '5 minutes ago' +%s)000000000" \
  --data-urlencode "end=$(date +%s)000000000"
```

Ou visualmente: Grafana em `http://localhost:3001` (admin/admin) → Explore →
datasource Loki → query `{job="mikrotik-firewall"}`.

## Coisas a checar se algo não funcionar

- **Firewall do Windows**: com a rede mirrored, o Windows Defender Firewall
  passa a filtrar diretamente o tráfego que chega na porta 1514/UDP (antes
  isso era mediado pelo NAT do WSL). Se o log não chegar, verificar se há
  uma regra de entrada liberando UDP 1514.
- **Promtail ainda de pé**: `wsl -d Ubuntu -u root -- systemctl status promtail`
- **Log de erros do Promtail**: `wsl -d Ubuntu -- journalctl -u promtail -n 50 --no-pager`
  (ou `cat ~/promtail.log` se ainda estiver rodando via nohup em vez de
  systemd).
- **Reiniciar Promtail após editar a config**:
  `wsl -d Ubuntu -u root -- systemctl restart promtail`
