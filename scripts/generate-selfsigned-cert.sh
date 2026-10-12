#!/usr/bin/env bash
set -euo pipefail

# Генерирует self-signed сертификат для локального HTTPS (nginx).
# Для прода используется Let's Encrypt через scripts/init-letsencrypt.sh.
CERT_DIR="$(cd "$(dirname "$0")/.." && pwd)/nginx/certs"
mkdir -p "$CERT_DIR"

if [[ -f "$CERT_DIR/selfsigned.crt" && -f "$CERT_DIR/selfsigned.key" ]]; then
  echo "Сертификат уже существует: $CERT_DIR/selfsigned.crt"
  exit 0
fi

openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
  -keyout "$CERT_DIR/selfsigned.key" \
  -out "$CERT_DIR/selfsigned.crt" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:vt-hash-checker.duckdns.org,IP:127.0.0.1"

chmod 600 "$CERT_DIR/selfsigned.key"
echo "Сгенерирован self-signed сертификат: $CERT_DIR/selfsigned.crt"
echo "Браузер будет ругаться на него — это нормально для локальной разработки (https://localhost)."
