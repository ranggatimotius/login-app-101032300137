#!/bin/bash
set -e
echo "╔══════════════════════════════════════════════╗"
echo "║    Snort IDS Container — NIM: 101032300137   ║"
echo "╚══════════════════════════════════════════════╝"

# Deteksi bridge interface Docker yang aktif
BRIDGE_IFACE=$(ip link show | grep -E "br-[a-z0-9]+" | grep "state UP" | \
    awk -F': ' '{print $2}' | head -n1)

if [ -n "$BRIDGE_IFACE" ]; then
    INTERFACE=$BRIDGE_IFACE
    echo "✅ Menggunakan Docker bridge: $INTERFACE"
else
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
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
    -A alert_fast \
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