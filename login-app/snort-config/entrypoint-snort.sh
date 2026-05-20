#!/bin/bash
set -e
echo "╔══════════════════════════════════════════════╗"
echo "║    Snort IDS Container — NIM: 101032300137   ║"
echo "╚══════════════════════════════════════════════╝"

# Deteksi interface yang memiliki IP 192.168.1.137
INTERFACE=$(ip -4 addr show | grep "inet 192.168.1.137" | awk '{print $NF}' | head -n1)

if [ -n "$INTERFACE" ]; then
    echo "✅ Menggunakan interface host (192.168.1.137): $INTERFACE"
else
    # Fallback: cari bridge Docker aktif
    INTERFACE=$(ip link show | grep -E "br-[a-z0-9]+" | grep "state UP" | \
        awk -F': ' '{print $2}' | head -n1)
    [ -z "$INTERFACE" ] && INTERFACE="eth0"
    echo "✅ Fallback interface: $INTERFACE"
fi

echo "✅ Snort version: $(snort --version 2>&1 | head -1)"
echo ""
echo "══════════════════════════════════════════════"
echo "  Snort 3 NIDS aktif — memonitor traffic..."
echo "══════════════════════════════════════════════"

# Jalankan Snort di background
snort \
    -c /etc/snort/snort.conf \
    -i $INTERFACE \
    -l /var/log/snort \
    -k none \
    --warn-all &

# Tunggu file alert terbuat
echo "⏳ Menunggu Snort siap..."
sleep 5

echo "✅ Snort aktif — menampilkan alert ke stdout..."
echo "══════════════════════════════════════════════"

# Tampilkan alert ke stdout agar muncul di docker logs
tail -f /var/log/snort/alert_fast.txt