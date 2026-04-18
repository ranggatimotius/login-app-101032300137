#!/bin/bash
# ══════════════════════════════════════════════════════════════
# test-snort.sh — Script Pengujian Snort IDS
# NIM: 101032300137
# ══════════════════════════════════════════════════════════════
# Cara pakai:
#   bash test-snort.sh          → test ke localhost
#   bash test-snort.sh 172.20.0.11  → test ke IP container web
# ══════════════════════════════════════════════════════════════

TARGET=${1:-localhost}
WEB_URL="https://$TARGET:3000"

echo "╔══════════════════════════════════════════════╗"
echo "║   Testing Snort IDS — NIM: 101032300137      ║"
echo "╚══════════════════════════════════════════════╝"
echo "Target : $TARGET"
echo "Web URL: $WEB_URL"
echo ""
echo "📌 Buka terminal lain dan jalankan:"
echo "   docker logs -f snort-101032300137"
echo "   untuk melihat alert real-time"
echo ""
read -p "Tekan ENTER untuk mulai testing..."
echo ""

# ─── TEST 1: ICMP ─────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 1: ICMP Ping"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Perintah: ping -c 5 $TARGET"
echo ""
ping -c 5 $TARGET
echo ""
echo "✅ Expected Alert Snort:"
echo "   [IDS-101032300137] ICMP Ping Inbound Detected"
echo ""
sleep 2

# ─── TEST 2: PORT SCAN ────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 2: Port Scanning dengan nmap"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Perintah: nmap -sS $TARGET -p 22,80,443,3000,3306,8080"
echo ""
if command -v nmap &>/dev/null; then
    nmap -sS $TARGET -p 22,80,443,3000,3306,8080 2>/dev/null || \
    nmap $TARGET -p 22,80,443,3000,3306,8080
else
    echo "nmap tidak tersedia, install dengan: sudo apt install nmap"
fi
echo ""
echo "✅ Expected Alert Snort:"
echo "   [IDS-101032300137] Port Scan Detected - SYN Flood"
echo "   [IDS-101032300137] Node.js App Port 3000 Access"
echo "   [IDS-101032300137] SUSPICIOUS MySQL Port 3306 Access"
echo ""
sleep 2

# ─── TEST 3: AKSES WEB BIASA ──────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 3: Akses Normal ke Web App"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Perintah: curl -sk $WEB_URL"
echo ""
curl -sk --max-time 5 $WEB_URL | grep -o "<title>.*</title>" | head -1 || \
    echo "Tidak dapat mengakses $WEB_URL"
echo ""
echo "✅ Expected Alert Snort:"
echo "   [IDS-101032300137] Node.js App Port 3000 Access"
echo ""
sleep 2

# ─── TEST 4: SQL INJECTION — OR 1=1 ──────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 4: SQL Injection — ' OR 1=1 --"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Mengirim payload ke form login..."
echo ""

curl -sk --max-time 5 \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=' OR 1=1 --&password=apapun" \
    $WEB_URL/login > /dev/null && echo "Request terkirim" || \
    echo "Request gagal (app mungkin tidak jalan)"

echo ""
echo "✅ Expected Alert Snort:"
echo "   [IDS-101032300137] SQL Injection - OR 1=1 in POST Body"
echo "   [IDS-101032300137] SQL Injection - Quote Comment Attack"
echo ""
sleep 2

# ─── TEST 5: SQL INJECTION — SELECT FROM ─────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 5: SQL Injection — SELECT * FROM"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

curl -sk --max-time 5 \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=' UNION SELECT * FROM users --" \
    $WEB_URL/login > /dev/null && echo "Request terkirim" || \
    echo "Request gagal"

echo ""
echo "✅ Expected Alert Snort:"
echo "   [IDS-101032300137] SQL Injection - SELECT FROM Detected"
echo "   [IDS-101032300137] SQL Injection - UNION SELECT Detected"
echo ""
sleep 2

# ─── TEST 6: MYSQL BLOCK ─────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 6: Akses MySQL dari luar (harus di-BLOCK)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

nc -zv -w 3 $TARGET 3306 2>&1 && \
    echo "⚠️  TERHUBUNG — ACL perlu dicek!" || \
    echo "✅ DI-BLOCK oleh iptables ACL (benar)"
echo ""

# ─── TAMPILKAN ALERT SNORT ────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "HASIL: Alert Snort yang tercatat"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
docker exec snort-101032300137 \
    cat /var/log/snort/alert 2>/dev/null | tail -30 || \
    echo "Lihat alert dengan: docker logs snort-101032300137"
echo ""
echo "══════════════════════════════════════════════"
echo "  Testing selesai!"
echo "  Lihat semua alert: docker logs -f snort-101032300137"
echo "  File alert       : docker exec snort-101032300137 cat /var/log/snort/alert"
echo "══════════════════════════════════════════════"
