#!/usr/bin/env bash
# ===========================================================================
# Red Team Agent - TLS Certificate Initialization
# ===========================================================================
# This script reads TLS_MODE from .env and generates certificates accordingly.
#
# Usage:
#   chmod +x scripts/init-tls.sh
#   ./scripts/init-tls.sh
# ===========================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SSL_DIR="$PROJECT_DIR/nginx/ssl"
ENV_FILE="$PROJECT_DIR/.env"

# -----------------------------------------------------------------------
# Load .env file
# -----------------------------------------------------------------------
if [ ! -f "$ENV_FILE" ]; then
    echo "ERROR: .env file not found at $ENV_FILE"
    echo "Copy .env.example to .env and configure it first."
    exit 1
fi

# Source .env (only export lines matching KEY=VALUE)
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

TLS_MODE="${TLS_MODE:-selfsigned}"
DOMAIN_NAME="${DOMAIN_NAME:-localhost}"
LETSENCRYPT_EMAIL="${LETSENCRYPT_EMAIL:-admin@example.com}"

echo "============================================="
echo "  TLS Certificate Initialization"
echo "============================================="
echo "  Mode:   $TLS_MODE"
echo "  Domain: $DOMAIN_NAME"
echo "============================================="

mkdir -p "$SSL_DIR"

# ===========================================================================
# Self-Signed Certificate
# ===========================================================================
if [ "$TLS_MODE" = "selfsigned" ]; then
    echo ""
    echo "[*] Generating self-signed certificate..."

    # Generate RSA 4096-bit private key and certificate with SAN
    openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
        -keyout "$SSL_DIR/privkey.pem" \
        -out "$SSL_DIR/fullchain.pem" \
        -subj "/C=US/ST=State/L=City/O=RedTeam/OU=Security/CN=$DOMAIN_NAME" \
        -addext "subjectAltName=DNS:$DOMAIN_NAME,DNS:localhost,IP:127.0.0.1"

    echo "[+] Self-signed certificate generated."

    # Generate Diffie-Hellman parameters
    if [ ! -f "$SSL_DIR/dhparam.pem" ]; then
        echo "[*] Generating DH parameters (this may take a while)..."
        openssl dhparam -out "$SSL_DIR/dhparam.pem" 4096
        echo "[+] DH parameters generated."
    else
        echo "[*] DH parameters already exist, skipping."
    fi

    echo ""
    echo "[+] Self-signed TLS setup complete."
    echo "    Certificate: $SSL_DIR/fullchain.pem"
    echo "    Private Key: $SSL_DIR/privkey.pem"
    echo "    DH Params:   $SSL_DIR/dhparam.pem"

# ===========================================================================
# Let's Encrypt Certificate
# ===========================================================================
elif [ "$TLS_MODE" = "letsencrypt" ]; then
    CERTBOT_DIR="$PROJECT_DIR/certbot"
    CERTBOT_WWW="$CERTBOT_DIR/www"
    CERTBOT_CONF="$CERTBOT_DIR/conf"

    mkdir -p "$CERTBOT_WWW" "$CERTBOT_CONF"

    echo ""
    echo "[*] Setting up Let's Encrypt for $DOMAIN_NAME..."

    # Step 1: Generate a temporary self-signed cert so nginx can start
    echo "[*] Generating temporary self-signed certificate for nginx bootstrap..."
    openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
        -keyout "$SSL_DIR/privkey.pem" \
        -out "$SSL_DIR/fullchain.pem" \
        -subj "/CN=$DOMAIN_NAME"

    # Generate DH parameters if not present
    if [ ! -f "$SSL_DIR/dhparam.pem" ]; then
        echo "[*] Generating DH parameters..."
        openssl dhparam -out "$SSL_DIR/dhparam.pem" 4096
    fi

    # Step 2: Start nginx with the temporary certificate
    echo "[*] Starting nginx for ACME challenge..."
    docker-compose -f "$PROJECT_DIR/docker-compose.prod.yml" up -d nginx

    # Wait for nginx to be ready
    echo "[*] Waiting for nginx to start..."
    sleep 5

    # Step 3: Run certbot with webroot authentication
    echo "[*] Requesting Let's Encrypt certificate..."
    docker run --rm \
        -v "$CERTBOT_CONF:/etc/letsencrypt" \
        -v "$CERTBOT_WWW:/var/www/certbot" \
        certbot/certbot certonly \
        --webroot \
        --webroot-path=/var/www/certbot \
        --email "$LETSENCRYPT_EMAIL" \
        --agree-tos \
        --no-eff-email \
        --force-renewal \
        -d "$DOMAIN_NAME"

    # Step 4: Copy certificates to nginx ssl directory
    echo "[*] Copying certificates..."
    cp "$CERTBOT_CONF/live/$DOMAIN_NAME/fullchain.pem" "$SSL_DIR/fullchain.pem"
    cp "$CERTBOT_CONF/live/$DOMAIN_NAME/privkey.pem" "$SSL_DIR/privkey.pem"

    # Step 5: Reload nginx with the real certificate
    echo "[*] Reloading nginx with Let's Encrypt certificate..."
    docker-compose -f "$PROJECT_DIR/docker-compose.prod.yml" exec nginx nginx -s reload

    echo ""
    echo "[+] Let's Encrypt TLS setup complete."
    echo "    Certificate: $SSL_DIR/fullchain.pem"
    echo "    Private Key: $SSL_DIR/privkey.pem"
    echo "    DH Params:   $SSL_DIR/dhparam.pem"
    echo ""
    echo "[!] Remember to enable the certbot service for auto-renewal:"
    echo "    docker-compose -f docker-compose.prod.yml --profile letsencrypt up -d certbot"

# ===========================================================================
# Invalid Mode
# ===========================================================================
else
    echo "ERROR: Invalid TLS_MODE '$TLS_MODE'"
    echo "Valid options: selfsigned, letsencrypt"
    exit 1
fi

echo ""
echo "Done."
