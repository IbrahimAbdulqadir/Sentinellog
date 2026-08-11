#!/bin/bash
# SentinelLog Installer
# Run this from inside the SentinelLog project folder, on the actual server
# you want it to watch (Ubuntu/Debian). Safe to re-run — it won't overwrite
# an existing .env or destroy an existing setup.
set -e

echo "=================================================="
echo "  SentinelLog Installer"
echo "=================================================="
echo

INSTALL_DIR="$(pwd)"

# ── 1. Python ──
if ! command -v python3 &> /dev/null; then
  echo "-> Python 3 not found, installing it..."
  sudo apt update && sudo apt install -y python3 python3-venv python3-pip
else
  echo "-> Python 3 already installed, good."
fi

# ── 2. Virtual environment ──
if [ ! -d "venv" ]; then
  echo "-> Creating a virtual environment..."
  python3 -m venv venv
else
  echo "-> Virtual environment already exists, reusing it."
fi

echo "-> Installing dependencies..."
./venv/bin/pip install --upgrade pip --quiet
./venv/bin/pip install -r requirements.txt --quiet

# ── 3. .env — only created once, never overwritten ──
if [ ! -f ".env" ]; then
  echo
  echo "-> No .env found, let's set one up now."
  SECRET_KEY=$(./venv/bin/python3 -c "import secrets; print(secrets.token_hex(32))")
  ENCRYPTION_KEY=$(./venv/bin/python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

  read -p "   Admin username [admin]: " ADMIN_USERNAME
  ADMIN_USERNAME=${ADMIN_USERNAME:-admin}

  read -sp "   Admin password (this protects the dashboard login): " ADMIN_PASSWORD
  echo
  while [ -z "$ADMIN_PASSWORD" ]; do
    read -sp "   Password can't be empty, try again: " ADMIN_PASSWORD
    echo
  done

  read -p "   OpenAI API key (optional — powers the AI alert explanations, press Enter to skip for now): " OPENAI_API_KEY

  cat > .env << EOF
SECRET_KEY=$SECRET_KEY
ADMIN_USERNAME=$ADMIN_USERNAME
ADMIN_PASSWORD=$ADMIN_PASSWORD
ENCRYPTION_KEY=$ENCRYPTION_KEY
OPENAI_API_KEY=$OPENAI_API_KEY
EOF
  chmod 600 .env
  echo "-> .env created (permissions locked to owner-only read/write)."
else
  echo "-> .env already exists, leaving it untouched."
fi

# ── 4. systemd service — this is what makes it survive a reboot ──
SERVICE_FILE="/etc/systemd/system/sentinellog.service"
CURRENT_USER=$(whoami)

echo "-> Setting up SentinelLog as a background service..."
sudo tee "$SERVICE_FILE" > /dev/null << EOF
[Unit]
Description=SentinelLog SIEM
After=network.target

[Service]
Type=simple
User=$CURRENT_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/app.py
Restart=on-failure
RestartSec=5
EnvironmentFile=$INSTALL_DIR/.env

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable sentinellog --quiet
sudo systemctl restart sentinellog

sleep 2
SERVER_IP=$(hostname -I | awk '{print $1}')

echo
echo "=================================================="
if sudo systemctl is-active --quiet sentinellog; then
  echo "  SentinelLog is running."
  echo "  Dashboard: http://$SERVER_IP:5050"
else
  echo "  Something went wrong. Check details with:"
  echo "  sudo systemctl status sentinellog"
fi
echo "=================================================="
echo
echo "Useful commands going forward:"
echo "  sudo systemctl status sentinellog   # is it running right now"
echo "  sudo systemctl restart sentinellog  # restart it"
echo "  sudo journalctl -u sentinellog -f   # watch its live output/errors"
echo
echo "It will now start automatically every time this server reboots."
