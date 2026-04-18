#!/bin/bash
# ══════════════════════════════════════════════════════════════
# entrypoint-snort.sh — Snort Container Entrypoint
# NIM: 101032300137
# ══════════════════════════════════════════════════════════════

set -e

echo "╔══════════════════════════════════════════════╗"
echo "║    Snort IDS Container — NIM: 101032300137   ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ─── Deteksi interface jaringan di dalam container ───────────
echo "🔍 Mendeteksi interface jaringan di dalam container..."

# Cara mengetahui interface di dalam container:
# 1. ip route → lihat interface default
# 2. ip link show → list semua interface
# 3. Dengan network_mode:host → pakai interface VM (eth0/ens33)

INTERFACE=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -n1)

if [ -z "$INTERFACE" ]; then
    INTERFACE=$(ip link show 2>/dev/null | grep -v lo | grep 'state UP' | \
                awk -F': ' '{print $2}' | head -n1)
fi

if [ -z "$INTERFACE" ]; then
    INTERFACE="eth0"
fi

echo "✅ Interface yang digunakan: $INTERFACE"
echo ""

# ─── Tampilkan info jaringan container ───────────────────────
echo "📡 Info jaringan:"
ip addr show $INTERFACE 2>/dev/null || ip addr show
echo ""

# ─── Validasi konfigurasi Snort ──────────────────────────────
echo "🔧 Validasi konfigurasi snort.conf..."
snort -T -c /etc/snort/snort.conf -i $INTERFACE 2>&1 | grep -E "Snort|ERROR|error|Warning" | tail -5
echo ""

# ─── Tampilkan rules yang aktif ──────────────────────────────
echo "📋 Rules yang dimuat:"
echo "   Local rules : /etc/snort/rules/local.rules"
grep -c "^alert" /etc/snort/rules/local.rules 2>/dev/null | \
    xargs -I{} echo "   Total rules : {} rules aktif"
echo ""

echo "══════════════════════════════════════════════"
echo "  ✅ Snort NIDS aktif — memonitor traffic..."
echo "  Interface : $INTERFACE"
echo "  Config    : /etc/snort/snort.conf"
echo "  Log       : /var/log/snort/alert"
echo "══════════════════════════════════════════════"
echo ""

# ─── Jalankan Snort mode console ─────────────────────────────
# -A console : tampilkan alert di console/stdout
# -q         : quiet mode (kurangi output non-alert)
# -c         : file konfigurasi
# -i         : interface yang dimonitor
# -l         : direktori log
exec snort \
    -A console \
    -q \
    -c /etc/snort/snort.conf \
    -i $INTERFACE \
    -l /var/log/snort
