#!/bin/bash
set -e

echo "╔══════════════════════════════════════════════╗"
echo "║    Snort IDS Container — NIM: 101032300137   ║"
echo "╚══════════════════════════════════════════════╝"

# Deteksi interface bridge Docker
# br-appnet = bridge interface app-network
# eth0 = interface default container (network_mode: host)
BRIDGE_IFACE="br-appnet-101032300137"
FALLBACK_IFACE=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -n1)

# Cek interface mana yang tersedia
if ip link show $BRIDGE_IFACE &>/dev/null; then
    INTERFACE=$BRIDGE_IFACE
    echo "✅ Menggunakan bridge interface: $INTERFACE"
elif ip link show br-appnet &>/dev/null; then
    INTERFACE="br-appnet"
    echo "✅ Menggunakan bridge interface: $INTERFACE"
else
    INTERFACE=${FALLBACK_IFACE:-eth0}
    echo "⚠️  Bridge tidak ditemukan, fallback ke: $INTERFACE"
fi

echo ""
echo "📡 Interface yang tersedia:"
ip link show | grep -E "^[0-9]+:" | awk '{print "   " $2}'
echo ""

# Set promiscuous mode pada interface
echo "🔧 Set promiscuous mode pada $INTERFACE..."
ip link set $INTERFACE promisc on 2>/dev/null || true

# Disable checksum offloading (KRITIS untuk Docker bridge)
echo "🔧 Disable checksum offloading..."
ethtool -K $INTERFACE rx off tx off gso off gro off tso off 2>/dev/null || \
    echo "   ethtool tidak tersedia, skip"

echo ""
echo "══════════════════════════════════════════════"
echo "  Snort 2.9 NIDS aktif"
echo "  Interface : $INTERFACE"
echo "  Checksums : disabled"
echo "══════════════════════════════════════════════"
echo ""

# Jalankan Snort 2.9 dengan:
# -k none              = KRITIS: abaikan semua checksum error
# -A console           = Print alerts ke stdout
exec snort \
    -c /etc/snort/snort.conf \
    -i $INTERFACE \
    -A console \
    -k none \
    -l /var/log/snort