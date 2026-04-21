#!/bin/bash

echo ""
echo "========================================================"
echo "   Snort IDS Container v3 -- NIM: 101032300137"
echo "========================================================"
echo ""
echo "[+] Interface : br-appnet (docker bridge)"
echo "[+] Rules     : $(grep -c '^alert' /etc/snort/rules/local.rules 2>/dev/null || echo 0) active rules"
echo ""
echo "========================================================"
echo "  Snort NIDS aktif -- memonitor traffic..."
echo "  Logging langsung ke DOCKER LOGS (stdout)"
echo "========================================================"
echo ""

mkdir -p /var/log/snort

# Snort sebagai PID 1 monitoring docker bridge interface
exec snort -c /etc/snort/snort.conf -i br-appnet -A alert_fast
