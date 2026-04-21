#!/bin/bash

echo ""
echo "========================================================"
echo "   Snort IDS Container -- NIM: 101032300137"
echo "========================================================"
echo ""
echo "[+] Interface : eth0"
echo "[+] Rules     : $(grep -c '^alert' /etc/snort/rules/local.rules 2>/dev/null || echo 0) active rules"
echo ""
echo "========================================================"
echo "  Snort NIDS aktif -- memonitor traffic di eth0..."
echo "  Alert file : /var/log/snort/alert_fast.txt"
echo "========================================================"
echo ""

mkdir -p /var/log/snort

# Snort sebagai PID 1 — container mati jika snort mati
exec snort -c /etc/snort/snort.conf -i eth0 -A alert_fast -l /var/log/snort
