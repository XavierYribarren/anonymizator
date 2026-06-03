#!/bin/bash
# deploy/deploy.sh — Initial deployment on VPS OVH (Ubuntu/Debian)
# Usage: bash deploy/deploy.sh votre-domaine.com

set -e

DOMAIN=${1:?"Usage: bash deploy.sh votre-domaine.com"}
APP_DIR="/opt/anonymizator"
APP_USER="anonymizator"

echo "=== Anonymizator Deployment ==="
echo "Domain: $DOMAIN"
echo "Directory: $APP_DIR"

# 1. System dependencies
echo "→ Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip nginx certbot python3-certbot-nginx git

# 2. Dedicated system user
if ! id "$APP_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /bin/false "$APP_USER"
    echo "→ User '$APP_USER' created."
fi

# 3. Clone or update repo
if [ -d "$APP_DIR/.git" ]; then
    echo "→ Updating existing installation..."
    git -C "$APP_DIR" pull
else
    echo "→ Cloning repository..."
    git clone https://github.com/VOTRE_USERNAME/anonymizator.git "$APP_DIR"
fi

# 4. Python virtual environment
echo "→ Setting up Python environment..."
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip setuptools
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/web/requirements_web.txt"

# 5. Uploads directory
mkdir -p "$APP_DIR/uploads"
chown -R "$APP_USER:$APP_USER" "$APP_DIR"
chmod 750 "$APP_DIR/uploads"

# 6. .env file (create from example if missing)
if [ ! -f "$APP_DIR/.env" ]; then
    cp "$APP_DIR/.env.example" "$APP_DIR/.env"
    sed -i "s|BASE_URL=http://localhost:8000|BASE_URL=https://$DOMAIN|g" "$APP_DIR/.env"
    echo "→ .env created. Edit $APP_DIR/.env to configure SMTP and other settings."
fi

# 7. Nginx
echo "→ Configuring Nginx..."
cp "$APP_DIR/deploy/nginx.conf" "/etc/nginx/sites-available/anonymizator"
sed -i "s/votre-domaine.com/$DOMAIN/g" "/etc/nginx/sites-available/anonymizator"
ln -sf "/etc/nginx/sites-available/anonymizator" "/etc/nginx/sites-enabled/anonymizator"
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

# 8. Let's Encrypt SSL
echo "→ Obtaining SSL certificate..."
certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email "admin@$DOMAIN" --redirect

# 9. systemd service
echo "→ Installing systemd service..."
cp "$APP_DIR/deploy/anonymizator.service" "/etc/systemd/system/anonymizator.service"
systemctl daemon-reload
systemctl enable anonymizator
systemctl restart anonymizator

# 10. Hourly cleanup via cron
echo "→ Setting up cleanup cron..."
(crontab -l 2>/dev/null; echo "0 * * * * $APP_DIR/venv/bin/python $APP_DIR/scripts/cleanup.py >> /var/log/anonymizator_cleanup.log 2>&1") | crontab -

echo ""
echo "=== Deployment complete ==="
echo "→ App running at https://$DOMAIN"
echo "→ Check status : systemctl status anonymizator"
echo "→ View logs    : journalctl -u anonymizator -f"
echo "→ Edit config  : nano $APP_DIR/.env && systemctl restart anonymizator"
