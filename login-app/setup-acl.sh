#!/bin/bash
# ══════════════════════════════════════════════════════════════
# setup-acl.sh — ACL iptables di Host VM
# NIM: 101032300137
# Jalankan: sudo bash setup-acl.sh
# ══════════════════════════════════════════════════════════════

echo "╔══════════════════════════════════════════════╗"
echo "║    Setup ACL iptables — NIM: 101032300137    ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Deteksi interface
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "Interface: $IFACE"
echo ""

# ─── Flush rules lama ────────────────────────────────────────
echo "🔄 Flush rules lama..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# ─── Default policy ──────────────────────────────────────────
iptables -P INPUT DROP
iptables -P FORWARD ACCEPT   # Docker butuh FORWARD
iptables -P OUTPUT ACCEPT

# ─── Allow loopback ──────────────────────────────────────────
echo "✅ Allow loopback..."
iptables -A INPUT -i lo -j ACCEPT

# ─── Allow established ───────────────────────────────────────
echo "✅ Allow established connections..."
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# ─── Allow Docker internal ───────────────────────────────────
echo "✅ Allow Docker internal traffic..."
iptables -A INPUT -i docker0 -j ACCEPT
iptables -A INPUT -i br-appnet-101032300137 -j ACCEPT

# ─── Allow SSH ───────────────────────────────────────────────
echo "✅ Allow SSH port 22..."
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# ─── Allow HTTP & HTTPS ──────────────────────────────────────
echo "✅ Allow HTTP port 80..."
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT

echo "✅ Allow HTTPS port 443..."
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT

# ─── Allow app ports ─────────────────────────────────────────
echo "✅ Allow Node.js port 3000..."
iptables -A INPUT -p tcp --dport 3000 -m state --state NEW -j ACCEPT

echo "✅ Allow phpMyAdmin port 8080..."
iptables -A INPUT -p tcp --dport 8080 -m state --state NEW -j ACCEPT

# ─── BLOCK MySQL dari luar ───────────────────────────────────
echo "🚫 BLOCK MySQL port 3306 dari luar..."
# Izinkan hanya dari Docker network internal
iptables -A INPUT -p tcp --dport 3306 -s 172.20.0.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 3306 -s 172.17.0.0/16 -j ACCEPT
iptables -A INPUT -p tcp --dport 3306 -s 127.0.0.1     -j ACCEPT
iptables -A INPUT -p tcp --dport 3306 -j DROP

# ─── ICMP — allow tapi Snort tetap catat ─────────────────────
echo "⚠️  Allow ICMP (Snort akan catat sebagai alert)..."
iptables -A INPUT -p icmp --icmp-type echo-request \
    -m limit --limit 10/second -j ACCEPT
# Ping berlebihan di-drop
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# ─── Log semua yang di-drop ──────────────────────────────────
echo "📝 Setup logging blocked traffic..."
iptables -A INPUT -j LOG \
    --log-prefix "[ACL-BLOCK-101032300137] " \
    --log-level 4
iptables -A INPUT -j DROP

# ─── Tampilkan hasil ─────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════"
echo "  SUMMARY ACL — NIM: 101032300137"
echo "══════════════════════════════════════════════"
echo "  ALLOW  ✅  Loopback"
echo "  ALLOW  ✅  Established connections"
echo "  ALLOW  ✅  Docker internal network"
echo "  ALLOW  ✅  SSH          :22"
echo "  ALLOW  ✅  HTTP         :80"
echo "  ALLOW  ✅  HTTPS        :443"
echo "  ALLOW  ✅  Node.js App  :3000"
echo "  ALLOW  ✅  phpMyAdmin   :8080"
echo "  ALLOW  ✅  ICMP/Ping    (rate limited)"
echo "  BLOCK  🚫  MySQL        :3306 dari luar"
echo "  LOG    📝  Semua traffic yang di-drop"
echo "══════════════════════════════════════════════"
echo ""
iptables -L INPUT -v -n --line-numbers
