#!/bin/bash

echo ""
echo "========================================================"
echo "   Snort IDS Container -- NIM: 101032300137"
echo "========================================================"
echo ""
echo "[+] Interface : br-appnet (docker bridge)"
echo "[+] Rules     : $(grep -c '^alert' /etc/snort/rules/local.rules 2>/dev/null || echo 0) active rules"
echo ""
echo "========================================================"
echo "  Snort NIDS aktif -- memonitor traffic..."
echo "  Alert file : /var/log/snort/alert_fast.txt"
echo "========================================================"
echo ""

mkdir -p /var/log/snort
touch /var/log/snort/alert_fast.txt

# Snort sebagai PID 1 monitoring docker bridge interface
exec snort -c /etc/snort/snort.conf -i br-appnet
