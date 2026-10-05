# =============================================================================
# MikroTik — Enviar logs via syslog para o OpenTelemetry Collector
# =============================================================================
# Cole no terminal do Winbox.
# Ajuste o IP COLLECTOR_HOST para o IP do servidor onde roda o docker-compose.
# =============================================================================

# Remove ação remota anterior se existir
/system logging action remove [find name=remote_otel]

# Cria ação de syslog apontando pro OTel Collector
/system logging action add \
    name=remote_otel \
    target=remote \
    remote=COLLECTOR_HOST \
    remote-port=1514 \
    bsd-syslog=yes \
    syslog-facility=local0 \
    syslog-severity=auto

# Envia todos os tópicos relevantes
/system logging remove [find action=remote_otel]
/system logging add topics=firewall action=remote_otel
/system logging add topics=dhcp action=remote_otel
/system logging add topics=dns action=remote_otel
/system logging add topics=system action=remote_otel
/system logging add topics=wireless action=remote_otel
/system logging add topics=critical action=remote_otel
/system logging add topics=error action=remote_otel
/system logging add topics=warning action=remote_otel
/system logging add topics=info action=remote_otel
