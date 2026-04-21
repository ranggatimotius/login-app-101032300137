#!/bin/bash
set -e

echo ""
echo "========================================================"
echo "   Snort IDS Container -- NIM: 101032300137"
echo "========================================================"
echo ""

INTERFACE=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -n1)

if [ -z "$INTERFACE" ]; then
    INTERFACE=$(ip link show 2>/dev/null | grep -v lo | grep 'state UP' | awk -F': ' '{print $2}' | head -n1)
fi

if [ -z "$INTERFACE" ]; then
    INTERFACE="eth0"
fi

echo "[+] Interface : $INTERFACE"
echo "[+] Snort     : $(snort --version 2>&1 | head -1)"

RULES_COUNT=$(grep -c "^alert" /etc/snort/rules/local.rules 2>/dev/null || echo "0")
echo "[+] Rules     : $RULES_COUNT active rules"
echo ""

echo "========================================================"
echo "  Snort NIDS aktif -- memonitor traffic..."
echo "  Interface : $INTERFACE"
echo "  Config    : /etc/snort/snort.conf"
echo "  Log dir   : /var/log/snort/"
echo "========================================================"
echo ""

mkdir -p /var/log/snort
touch /var/log/snort/alert_fast.txt

tail -f /var/log/snort/alert_fast.txt &
TAIL_PID=$!

cleanup() {
    kill $TAIL_PID 2>/dev/null || true
    exit 0
}
trap cleanup EXIT INT TERM

snort \
    -c /etc/snort/snort.conf \
    -i $INTERFACE \
    -l /var/log/snort \
    -q
