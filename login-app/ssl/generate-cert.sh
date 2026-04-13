#!/bin/sh
# Generate self-signed SSL certificate
echo "🔐 Generating self-signed SSL certificate..."

openssl req -x509 \
  -newkey rsa:4096 \
  -keyout /app/ssl/server.key \
  -out /app/ssl/server.cert \
  -days 365 \
  -nodes \
  -subj "/C=ID/ST=Jakarta/L=Jakarta/O=SecureApp-101032300137/OU=IT/CN=localhost" \
  2>/dev/null

echo "✅ SSL certificate generated!"
echo "   Key:  /ssl/server.key"
echo "   Cert: /ssl/server.cert"
