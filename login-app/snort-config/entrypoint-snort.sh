#!/bin/bash

echo ""
echo "========================================================"
echo "   Snort IDS Container -- NIM: 101032300137"
echo "========================================================"
echo ""

INTERFACE="any"

echo "[+] Interface : $INTERFACE (all interfaces)"
echo "[+] Rules     : $(grep -c '^alert' /etc/snort/rules/local.rules 2>/dev/null || echo 0) active rules"
echo ""
echo "========================================================"
echo "  Snort NIDS aktif -- memonitor traffic..."
echo "========================================================"
echo ""

mkdir -p /var/log/snort

# Snort outputs alerts to stdout (file=false in snort.conf)
# tee writes to both stdout (docker logs) AND file (host access)
snort -c /etc/snort/snort.conf -i "$INTERFACE" -l /var/log/snort 2>&1 | tee -a /var/log/snort/alert_fast.txt
