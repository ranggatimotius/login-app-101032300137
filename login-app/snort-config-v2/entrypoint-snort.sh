#!/bin/bash
set -e

echo "╔══════════════════════════════════════════════╗"
echo "║    Snort IDS Container — NIM: 101032300137   ║"
echo "╚══════════════════════════════════════════════╝"

# Deteksi interface bridge Docker
# br-appnet = bridge interface dari docker-compose network
BRIDGE_IFACE="br-appnet"
FALLBACK_IFACE=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -n1)

# Cek interface mana yang tersedia
if ip link show "$BRIDGE_IFACE" &>/dev/null; then
    INTERFACE="$BRIDGE_IFACE"
    echo "✅ Menggunakan bridge interface: $INTERFACE"
else
    INTERFACE="${FALLBACK_IFACE:-eth0}"
    echo "⚠️  Bridge tidak ditemukan, fallback ke: $INTERFACE"
fi

echo ""
echo "📡 Interface yang tersedia:"
ip link show | grep -E "^[0-9]+:" | awk '{print "   " $2}'
echo ""

# Set promiscuous mode pada interface
echo "🔧 Set promiscuous mode pada $INTERFACE..."
ip link set "$INTERFACE" promisc on 2>/dev/null || true

# Disable checksum offloading (penting untuk Docker bridge)
echo "🔧 Disable checksum offloading..."
ethtool -K "$INTERFACE" rx off tx off gso off gro off tso off 2>/dev/null || \
    echo "   ethtool tidak tersedia atau interface tidak support, skip"

# Pastikan direktori log ada
mkdir -p /var/log/snort

echo ""
echo "══════════════════════════════════════════════"
echo "  Snort 2.9 NIDS aktif"
echo "  Interface : $INTERFACE"
echo "  Mode      : afpacket DAQ (passive)"
echo "  Checksums : disabled (checksum_mode: none)"
echo "  Log       : /var/log/snort + stdout"
echo "══════════════════════════════════════════════"
echo ""

# Jalankan Snort 2.9 dengan:
# -c    = config file
# -i    = interface
# -A console = alert ke stdout (Snort 2.9 format)
# -k none   = KRITIS: abaikan semua checksum error
# -l    = log directory
# -D hilangkan karena kita mau foreground
# --daq afpacket = gunakan afpacket DAQ
# --daq-var     = konfigurasi buffer
exec snort \
    -c /etc/snort/snort.conf \
    -i "$INTERFACE" \
    -A console \
    -k none \
    -l /var/log/snort \
    --daq afpacket \
    --daq-var buffer_size_mb=128
