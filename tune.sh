#!/usr/bin/env bash
set -euo pipefail

# Require Linux
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "❌ This script is only supported on Linux."; exit 1
fi

# Require service name
if [[ $# -lt 1 ]]; then
  echo "❌ Usage: $0 <service-name>"; exit 1
fi
SERVICE="$1"

# Ensure service exists (works whether or not it's active)
if ! systemctl status "${SERVICE}.service" >/dev/null 2>&1 && \
   ! systemctl status "${SERVICE}" >/dev/null 2>&1; then
  echo "❌ Service '${SERVICE}' not found."; exit 1
fi

echo "🛠️ Applying high concurrency network tuning for '${SERVICE}'..."

# 0) Try to ensure required kernel modules (best-effort; ignore failures)
if command -v modprobe >/dev/null 2>&1; then
  sudo modprobe tcp_bbr 2>/dev/null || true
  sudo modprobe sch_fq  2>/dev/null || true
fi

# 1) sysctl tuning (avoid obsolete/fragile keys)
sudo install -m 0644 /dev/null /etc/sysctl.d/99-high-scale.conf
sudo tee /etc/sysctl.d/99-high-scale.conf >/dev/null <<'EOF'
fs.file-max = 2097152

net.core.somaxconn = 65535
net.core.netdev_max_backlog = 250000

# QDisc for pacing
net.core.default_qdisc = fq

# SYN backlog and syncookies (keep if you face SYN floods)
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_syncookies = 1

# Port range for many outgoing conns
net.ipv4.ip_local_port_range = 1024 65535

# Socket buffer ceilings and defaults
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Keepalive (reasonable)
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5

# FIN timeout (be careful lowering too much)
net.ipv4.tcp_fin_timeout = 10

# Congestion control (fallback to cubic if bbr isn’t available)
net.ipv4.tcp_congestion_control = bbr
EOF

# Apply sysctls (tolerate missing keys)
if ! sudo sysctl --system; then
  echo "⚠️ Some sysctl keys failed to apply; continuing (likely kernel/feature mismatch)."
fi

# If bbr isn't available, fallback to cubic
if ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
  echo "ℹ️ BBR not available; falling back to cubic."
  sudo sysctl -w net.ipv4.tcp_congestion_control=cubic || true
fi

# 2) Security limits via drop-in file (avoid editing the global file)
echo "🔧 Setting pam limits (for shells/login sessions)…"
sudo install -m 0644 /dev/null /etc/security/limits.d/99-high-scale.conf
sudo tee /etc/security/limits.d/99-high-scale.conf >/dev/null <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
EOF

# 3) Systemd service overrides (the ones that matter for services)
echo "⚙️ Configuring systemd service: ${SERVICE}"
SYSTEMD_DIR="/etc/systemd/system/${SERVICE}.service.d"
sudo mkdir -p "$SYSTEMD_DIR"
sudo tee "$SYSTEMD_DIR/override.conf" >/dev/null <<'EOF'
[Service]
# File descriptors
LimitNOFILE=1048576
# Optional: allow many tasks/threads
TasksMax=infinity
# Optional: if you create many processes
#LimitNPROC=1048576
# Optional: if you use mlock (e.g., high-perf net, DPUs)
#LimitMEMLOCK=infinity
EOF

# 4) Reload and restart
echo "🔄 Reloading systemd and restarting ${SERVICE}…"
sudo systemctl daemon-reload
sudo systemctl restart "$SERVICE"

# 5) Quick verification
echo "🔍 Verifying applied limits:"
systemctl show -p LimitNOFILE -p TasksMax "$SERVICE"
sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc | sed 's/^/  /'

echo "✅ High concurrency tuning applied for '${SERVICE}'. A reboot may be required for full effect."
