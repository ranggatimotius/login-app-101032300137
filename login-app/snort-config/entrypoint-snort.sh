#!/bin/bash
set -e

echo "╔══════════════════════════════════════════════╗"
echo "║    Snort IDS Container — NIM: 101032300137   ║"
echo "╚══════════════════════════════════════════════╝"

INTERFACE=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -n1)
[ -z "$INTERFACE" ] && INTERFACE="eth0"

echo "✅ Interface: $INTERFACE"
echo "✅ Snort version: $(snort --version 2>&1 | head -1)"
echo ""
echo "══════════════════════════════════════════════"
echo "  Snort 3 NIDS aktif — memonitor traffic..."
echo "══════════════════════════════════════════════"

exec snort \
    -c /etc/snort/snort.conf \
    -i $INTERFACE \
    -A alert_fast \
    -l /var/log/snort \
    --warn-all
