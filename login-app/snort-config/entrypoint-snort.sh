#!/bin/bash

echo ""
echo "========================================================"
echo "   Snort IDS Container -- NIM: 101032300137"
echo "========================================================"
echo ""

INTERFACE=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -n1)
if [ -z "$INTERFACE" ]; then
    INTERFACE="eth0"
fi

echo "[+] Interface : $INTERFACE"
echo "[+] Rules     : $(grep -c '^alert' /etc/snort/rules/local.rules 2>/dev/null || echo 0) active rules"
echo ""
echo "========================================================"
echo "  Snort NIDS aktif -- memonitor traffic..."
echo "  Log dir   : /var/log/snort/"
echo "========================================================"
echo ""

mkdir -p /var/log/snort
touch /var/log/snort/alert_fast.txt

# Tail alert file to stdout for docker logs visibility
tail -f /var/log/snort/alert_fast.txt &

# Replace shell with snort process (becomes PID 1)
exec snort -c /etc/snort/snort.conf -i "$INTERFACE" -l /var/log/snort
