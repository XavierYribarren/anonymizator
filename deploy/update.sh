#!/bin/bash
# deploy/update.sh — Update an existing Anonymizator installation
set -e

APP_DIR="/opt/anonymizator"

echo "→ Pulling latest changes..."
git -C "$APP_DIR" pull

echo "→ Updating dependencies..."
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/web/requirements_web.txt"

echo "→ Restarting service..."
systemctl restart anonymizator

echo "Update complete."
systemctl status anonymizator --no-pager
