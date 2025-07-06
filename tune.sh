#!/usr/bin/env bash
set -euo pipefail

# Check for Linux OS
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "❌ This script is only supported on Linux."
  exit 1
fi

# Require service name as first argument
if [[ $# -lt 1 ]]; then
  echo "❌ Usage: $0 <service-name>"
  exit 1
fi

SERVICE="$1"

# Check if systemd service exists
if ! systemctl list-units --type=service --all | grep -qE "^${SERVICE}(\.service)?"; then
  echo "❌ Service '${SERVICE}' not found."
  exit 1
fi

echo "🛠️ Applying high concurrency network tuning for '${SERVICE}'..."

# 1. Apply sysctl tuning
cat <<EOF | sudo tee /etc/sysctl.d/99-high-scale.conf > /dev/null
fs.file-max = 2097152
net.ipv4.tcp_max_syn_backlog = 16384
net.core.somaxconn = 16384
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_syncookies = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_fastopen = 3
EOF

sudo sysctl --system

# 2. Update security limits
echo "🔧 Updating limits.conf..."
if [[ -f /etc/security/limits.conf ]]; then
  sudo cp /etc/security/limits.conf /etc/security/limits.conf.bak
fi

sudo sed -i '/^\* soft nofile/d;/^\* hard nofile/d' /etc/security/limits.conf
echo '* soft nofile 1048576' | sudo tee -a /etc/security/limits.conf > /dev/null
echo '* hard nofile 1048576' | sudo tee -a /etc/security/limits.conf > /dev/null

# 3. Systemd service override
echo "⚙️ Configuring systemd service: $SERVICE"
SYSTEMD_DIR="/etc/systemd/system/${SERVICE}.service.d"
sudo mkdir -p "$SYSTEMD_DIR"

cat <<EOF | sudo tee "$SYSTEMD_DIR/override.conf" > /dev/null
[Service]
LimitNOFILE=1048576
EOF

# 4. Reload systemd and restart service
echo "🔄 Reloading systemd..."
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl restart "$SERVICE"

echo "✅ High concurrency tuning applied for '${SERVICE}'. A reboot may be required for full effect."
