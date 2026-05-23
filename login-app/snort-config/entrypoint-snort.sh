#!/bin/bash
set -e
echo "╔══════════════════════════════════════════════╗"
echo "║    Snort IDS Container — NIM: 101032300137   ║"
echo "╚══════════════════════════════════════════════╝"

# Deteksi Docker bridge dengan subnet 192.168.1.0/24
INTERFACE=$(ip -4 addr show | grep "inet 192.168.1.1/" | awk '{print $NF}' | head -n1)

if [ -n "$INTERFACE" ]; then
    echo "✅ Menggunakan Docker bridge (192.168.1.x): $INTERFACE"
else
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

# Pastikan file ada agar tail tidak error
touch /var/log/snort/alert_fast.txt

# Tampilkan alert ke stdout (jalankan di background)
tail -f /var/log/snort/alert_fast.txt &

echo "⏳ Memulai Snort di foreground..."
# Jalankan Snort di foreground agar jika crash, error-nya terlihat di log container
exec snort \
    -c /etc/snort/snort.conf \
    -i $INTERFACE \
    -l /var/log/snort \
    -k none \
    --warn-all