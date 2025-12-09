#!/bin/bash
# Setup Graylog inputs and dashboards

GRAYLOG_HOST="localhost:9000"
USERNAME="admin"
PASSWORD="admin"

# Create Syslog input
curl -u $USERNAME:$PASSWORD -X POST "http://$GRAYLOG_HOST/api/system/inputs" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "ASM Syslog Input",
    "type": "org.graylog2.inputs.syslog.tcp.SyslogTCPInput",
    "global": true,
    "configuration": {
      "port": 1514,
      "bind_address": "0.0.0.0"
    }
  }'

# Create GELF input
curl -u $USERNAME:$PASSWORD -X POST "http://$GRAYLOG_HOST/api/system/inputs" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "ASM GELF Input",
    "type": "org.graylog2.inputs.gelf.tcp.GELFTCPInput",
    "global": true,
    "configuration": {
      "port": 5555,
      "bind_address": "0.0.0.0"
    }
  }'

# Import dashboards
curl -u $USERNAME:$PASSWORD -X POST "http://$GRAYLOG_HOST/api/dashboards" \
  -H "Content-Type: application/json" \
  --data-binary @src/graylog_integration/dashboards/asm_dashboard.json