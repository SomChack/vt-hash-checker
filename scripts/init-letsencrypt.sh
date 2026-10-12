#!/usr/bin/env bash
set -euo pipefail

# Первичный выпуск сертификата Let's Encrypt для прода и перезапуск nginx.
# Использование:  ./scripts/init-letsencrypt.sh [domain] [email] [staging]
#   domain  — по умолчанию vt-hash-checker.duckdns.org
#   email   — email для уведомлений Let's Encrypt (обязателен)
#   staging — 1, чтобы сначала проверить на staging-сервере LE (необязательно)
DOMAIN="${1:-vt-hash-checker.duckdns.org}"
EMAIL="${2:-}"
STAGING="${3:-0}"

if [[ -z "$EMAIL" ]]; then
  echo "Usage: $0 [domain] [email] [staging=0|1]"
  echo "Example: $0 vt-hash-checker.duckdns.org you@example.com"
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONF="$ROOT/certbot/conf"
WWW="$ROOT/certbot/www"
LIVE="$CONF/live/$DOMAIN"
mkdir -p "$LIVE" "$WWW"

# 1. Временный self-signed сертификат, чтобы nginx мог стартовать до выпуска настоящего.
if [[ ! -f "$LIVE/fullchain.pem" ]]; then
  echo "Создаю временный сертификат для $DOMAIN (чтобы nginx стартовал)..."
  openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
    -keyout "$LIVE/privkey.pem" \
    -out "$LIVE/fullchain.pem" \
    -subj "/CN=$DOMAIN" >/dev/null 2>&1
fi

# 2. Поднимаем nginx (сервис app тоже поднимется через depends_on).
echo "Запускаю nginx..."
(cd "$ROOT" && docker compose -f docker-compose.prod.yml up -d nginx)

# 3. Выпускаем настоящий сертификат (webroot, HTTP-01).
echo "Запрашиваю сертификат Let's Encrypt для $DOMAIN..."
CERTBOT_ARGS=(certonly --webroot -w /var/www/certbot -d "$DOMAIN" --email "$EMAIL" --agree-tos --no-eff-email)
if [[ "$STAGING" == "1" ]]; then
  CERTBOT_ARGS+=(--staging)
fi

docker run --rm \
  -v "$CONF:/etc/letsencrypt" \
  -v "$WWW:/var/www/certbot" \
  certbot/certbot "${CERTBOT_ARGS[@]}"

# 4. Перечитываем конфиг nginx с настоящим сертификатом.
echo "Перезагружаю nginx..."
(cd "$ROOT" && docker compose -f docker-compose.prod.yml exec nginx nginx -s reload)

echo "Готово. HTTPS доступен по https://$DOMAIN"
echo "Автопродление выполняет контейнер certbot (раз в 12 часов)."
