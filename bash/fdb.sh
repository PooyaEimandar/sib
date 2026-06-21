#!/usr/bin/env bash
# bash/fdb.sh
# FoundationDB install/uninstall script for macOS and Linux
# Supports:
#   - macOS arm64
#   - Linux amd64 (Debian/Ubuntu with apt)
# Usage:
#   ./fdb.sh install        # Install FoundationDB (default)
#   ./fdb.sh uninstall      # Uninstall FoundationDB
#   ./fdb.sh docker         # Start FoundationDB in Docker for local tests
#   ./fdb.sh help           # Show help

set -euo pipefail
IFS=$'\n\t'

# Colors (safe defaults)
COLOR_GREEN="${COLOR_GREEN:-\033[0;32m}"
COLOR_RED="${COLOR_RED:-\033[0;31m}"
COLOR_YELLOW="${COLOR_YELLOW:-\033[0;33m}"
COLOR_OFF="${COLOR_OFF:-\033[0m}"

FDB_VERSION="7.3.69"
FDB_BASE_URL="https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}"
FDB_IMAGE="${FDB_IMAGE:-foundationdb/foundationdb:${FDB_VERSION}}"
FDB_CONTAINER="${FDB_CONTAINER:-sib-fdb}"
FDB_PORT="${FDB_PORT:-4500}"
FDB_DIR="${FDB_DIR:-.fdb}"
FDB_CLUSTER_FILE="${FDB_CLUSTER_FILE:-${FDB_DIR}/fdb.cluster}"
FDB_DOCKER_PLATFORM="${FDB_DOCKER_PLATFORM:-linux/amd64}"

ARCH="$(uname -m)"
PLATFORM="$(uname -s)"

is_command_exists() { command -v "$1" >/dev/null 2>&1; }

need_sudo() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    if ! is_command_exists sudo; then
      echo -e "${COLOR_RED}Error: sudo is required but not installed.${COLOR_OFF}"
      exit 1
    fi
  fi
}

usage() {
  cat <<EOF
Usage:
  $0 install        Install FoundationDB (default)
  $0 uninstall      Uninstall FoundationDB
  $0 docker         Start local FoundationDB in Docker
  $0 docker start   Start local FoundationDB in Docker
  $0 docker stop    Stop and remove the Docker FoundationDB server
  $0 docker restart Restart the Docker FoundationDB server
  $0 docker status  Show Docker FoundationDB status
  $0 help           Show this help

Notes:
  - macOS: this script supports arm64 only.
  - Linux: this script supports Debian/Ubuntu (apt) on amd64 only.
  - To keep macOS env exports in your current shell, run:
      source $0 install
  - Docker local test cluster writes:
      ${FDB_CLUSTER_FILE}

Run Docker-backed tests with:
  SIB_FDB_CLUSTER_FILE=${FDB_CLUSTER_FILE} cargo test --no-default-features --features "rt-tokio db-fdb" database::fdb -- --test-threads=1
EOF
}

curl_fetch() {
  local url="$1"
  local out="$2"
  if ! is_command_exists curl; then
    echo -e "${COLOR_RED}Error: curl is required but not installed.${COLOR_OFF}"
    exit 1
  fi
  echo -e "${COLOR_GREEN}Downloading:${COLOR_OFF} $url"
  curl -fL --retry 3 --retry-delay 1 -o "$out" "$url"
}

verify_fdb() {
  echo -e "${COLOR_GREEN}Verifying FoundationDB installation...${COLOR_OFF}"
  if ! is_command_exists fdbcli; then
    echo -e "${COLOR_RED}Error: fdbcli not found after install.${COLOR_OFF}"
    exit 1
  fi

  local v
  v="$(fdbcli --version 2>/dev/null || true)"
  echo -e "${COLOR_GREEN}fdbcli --version =>${COLOR_OFF} $v"

  if echo "$v" | grep -q "$FDB_VERSION"; then
    echo -e "${COLOR_GREEN}FoundationDB ${FDB_VERSION} installed successfully!${COLOR_OFF}"
  else
    echo -e "${COLOR_RED}Error: Installed FoundationDB version does not match expected ${FDB_VERSION}.${COLOR_OFF}"
    exit 1
  fi
}

configure_fdb() {
  echo -e "${COLOR_GREEN}Configuring FoundationDB local database...${COLOR_OFF}"
  for _ in $(seq 1 30); do
    if fdbcli --exec status >/dev/null 2>&1; then
      echo -e "${COLOR_GREEN}FoundationDB local database is ready.${COLOR_OFF}"
      return
    fi
    if fdbcli --exec "configure new single memory" >/dev/null 2>&1; then
      echo -e "${COLOR_GREEN}FoundationDB local database is configured.${COLOR_OFF}"
      return
    fi
    sleep 1
  done

  echo -e "${COLOR_RED}Error: FoundationDB did not become configurable in time.${COLOR_OFF}"
  exit 1
}

require_docker() {
  if ! is_command_exists docker; then
    echo -e "${COLOR_RED}Error: docker is required.${COLOR_OFF}"
    exit 1
  fi
}

write_docker_cluster_file() {
  mkdir -p "${FDB_DIR}"
  printf 'docker:docker@127.0.0.1:%s\n' "${FDB_PORT}" >"${FDB_CLUSTER_FILE}"
}

docker_start_fdb() {
  require_docker
  write_docker_cluster_file

  if docker ps --format '{{.Names}}' | grep -qx "${FDB_CONTAINER}"; then
    echo -e "${COLOR_YELLOW}FoundationDB container is already running:${COLOR_OFF} ${FDB_CONTAINER}"
  else
    docker rm -f "${FDB_CONTAINER}" >/dev/null 2>&1 || true
    docker run \
      --detach \
      --name "${FDB_CONTAINER}" \
      --platform "${FDB_DOCKER_PLATFORM}" \
      --env FDB_NETWORKING_MODE=host \
      --env "FDB_CLUSTER_FILE_CONTENTS=docker:docker@127.0.0.1:${FDB_PORT}" \
      --publish "127.0.0.1:${FDB_PORT}:4500" \
      "${FDB_IMAGE}" >/dev/null
  fi

  echo -e "${COLOR_GREEN}Waiting for FoundationDB Docker server...${COLOR_OFF}"
  for _ in $(seq 1 60); do
    if docker exec "${FDB_CONTAINER}" timeout 5 fdbcli --exec status >/dev/null 2>&1; then
      echo -e "${COLOR_GREEN}FoundationDB Docker server is ready.${COLOR_OFF}"
      echo "Cluster file: ${FDB_CLUSTER_FILE}"
      return
    fi
    if docker exec "${FDB_CONTAINER}" timeout 5 fdbcli --exec "configure new single memory" >/dev/null 2>&1; then
      echo -e "${COLOR_GREEN}FoundationDB Docker server is ready.${COLOR_OFF}"
      echo "Cluster file: ${FDB_CLUSTER_FILE}"
      return
    fi
    sleep 1
  done

  echo -e "${COLOR_RED}Error: FoundationDB Docker server did not become ready in time.${COLOR_OFF}" >&2
  docker logs "${FDB_CONTAINER}" >&2 || true
  exit 1
}

docker_stop_fdb() {
  require_docker
  docker rm -f "${FDB_CONTAINER}" >/dev/null 2>&1 || true
}

docker_status_fdb() {
  require_docker
  docker ps --filter "name=^/${FDB_CONTAINER}$" --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
}

do_docker() {
  local docker_action="${1:-start}"
  case "$docker_action" in
    start) docker_start_fdb ;;
    stop) docker_stop_fdb ;;
    restart)
      docker_stop_fdb
      docker_start_fdb
      ;;
    status) docker_status_fdb ;;
    help|-h|--help) usage ;;
    *)
      echo -e "${COLOR_RED}Unknown docker action: ${docker_action}${COLOR_OFF}"
      usage
      exit 1
      ;;
  esac
}

export_macos_link_env() {
  export FDB_CLIENT_LIB_DIR="/usr/local/lib"
  export LIBRARY_PATH="/usr/local/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
  export DYLD_FALLBACK_LIBRARY_PATH="/usr/local/lib${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"

  echo -e "${COLOR_YELLOW}Exported (current shell only):${COLOR_OFF}"
  echo "  FDB_CLIENT_LIB_DIR=$FDB_CLIENT_LIB_DIR"
  echo "  LIBRARY_PATH=$LIBRARY_PATH"
  echo "  DYLD_FALLBACK_LIBRARY_PATH=$DYLD_FALLBACK_LIBRARY_PATH"
  echo -e "${COLOR_YELLOW}Tip:${COLOR_OFF} run as  source ./install_fdb.sh install  to keep exports in your terminal."
}

install_fdb_macos_arm64() {
  if [[ "$ARCH" != "arm64" ]]; then
    echo -e "${COLOR_RED}Unsupported architecture for this script on macOS: $ARCH (only arm64 supported).${COLOR_OFF}"
    exit 1
  fi

  need_sudo

  local workdir=""
  workdir="$(mktemp -d)"
  trap '[[ -n "${workdir:-}" ]] && rm -rf "$workdir"' EXIT

  local pkg="FoundationDB-${FDB_VERSION}_arm64.pkg"
  local pkg_path="$workdir/$pkg"

  echo -e "${COLOR_GREEN}Installing FoundationDB on macOS (arm64)...${COLOR_OFF}"
  curl_fetch "$FDB_BASE_URL/$pkg" "$pkg_path"

  echo -e "${COLOR_GREEN}Running macOS installer...${COLOR_OFF}"
  sudo installer -pkg "$pkg_path" -target /

  export_macos_link_env
  verify_fdb
  configure_fdb
}

install_fdb_linux_amd64() {
  if [[ "$ARCH" != "x86_64" ]]; then
    echo -e "${COLOR_RED}Unsupported architecture for this script on Linux: $ARCH (only x86_64/amd64 supported).${COLOR_OFF}"
    exit 1
  fi

  need_sudo

  if ! is_command_exists apt; then
    echo -e "${COLOR_RED}Error: This Linux installer supports Debian/Ubuntu (apt) only.${COLOR_OFF}"
    exit 1
  fi

  export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"
  export NEEDRESTART_MODE="${NEEDRESTART_MODE:-a}"

  local workdir=""
  workdir="$(mktemp -d)"
  trap '[[ -n "${workdir:-}" ]] && rm -rf "$workdir"' EXIT

  local client_deb="foundationdb-clients_${FDB_VERSION}-1_amd64.deb"
  local server_deb="foundationdb-server_${FDB_VERSION}-1_amd64.deb"
  local client_path="$workdir/$client_deb"
  local server_path="$workdir/$server_deb"

  echo -e "${COLOR_GREEN}Installing FoundationDB on Linux (amd64, apt)...${COLOR_OFF}"
  echo -e "${COLOR_GREEN}Updating package list...${COLOR_OFF}"
  sudo apt update -y

  echo -e "${COLOR_GREEN}Installing dependencies...${COLOR_OFF}"
  sudo apt install -y curl ca-certificates

  curl_fetch "$FDB_BASE_URL/$client_deb" "$client_path"
  curl_fetch "$FDB_BASE_URL/$server_deb" "$server_path"

  echo -e "${COLOR_GREEN}Installing .deb packages...${COLOR_OFF}"
  sudo apt install -y "$client_path" "$server_path"

  if is_command_exists systemctl && pidof systemd >/dev/null 2>&1; then
    echo -e "${COLOR_GREEN}Enabling and starting FoundationDB service...${COLOR_OFF}"
    if systemctl list-unit-files | grep -q '^foundationdb\.service'; then
      sudo systemctl enable --now foundationdb.service
    else
      sudo systemctl enable --now foundationdb || true
    fi
  else
    echo -e "${COLOR_YELLOW}systemd not detected; skipping service enable/start.${COLOR_OFF}"
  fi

  verify_fdb
  configure_fdb
}

uninstall_fdb_macos_arm64() {
  if [[ "$ARCH" != "arm64" ]]; then
    echo -e "${COLOR_RED}Unsupported architecture for this script on macOS: $ARCH (only arm64 supported).${COLOR_OFF}"
    exit 1
  fi

  need_sudo

  echo -e "${COLOR_YELLOW}Uninstalling FoundationDB on macOS...${COLOR_OFF}"
  echo -e "${COLOR_YELLOW}This removes common installed paths and launchd items (best-effort).${COLOR_OFF}"
  echo -e "${COLOR_YELLOW}Your data/config may still exist depending on prior setup.${COLOR_OFF}"

  # Stop launchd services if present
  sudo launchctl list | grep -qi foundationdb && {
    echo -e "${COLOR_YELLOW}Attempting to unload launchd items...${COLOR_OFF}"
    sudo launchctl remove com.foundationdb.fdbmonitor 2>/dev/null || true
    sudo launchctl remove com.apple.foundationdb.fdbmonitor 2>/dev/null || true
  } || true

  # Kill running processes
  sudo pkill -x fdbserver 2>/dev/null || true
  sudo pkill -x fdbmonitor 2>/dev/null || true

  # Remove typical installed files
  sudo rm -f /usr/local/bin/fdbcli /usr/local/bin/fdbserver /usr/local/bin/fdbmonitor 2>/dev/null || true
  sudo rm -f /usr/local/lib/libfdb_c.dylib 2>/dev/null || true
  sudo rm -rf /usr/local/include/foundationdb 2>/dev/null || true

  # Remove common launchd plists
  sudo rm -f /Library/LaunchDaemons/com.foundationdb.*.plist /Library/LaunchDaemons/com.apple.foundationdb.*.plist 2>/dev/null || true
  sudo rm -f /Library/LaunchAgents/com.foundationdb.*.plist /Library/LaunchAgents/com.apple.foundationdb.*.plist 2>/dev/null || true

  echo -e "${COLOR_GREEN}macOS uninstall completed (best-effort).${COLOR_OFF}"
  echo -e "${COLOR_YELLOW}If you also want to remove data/config, check:${COLOR_OFF}"
  echo "  /usr/local/etc/foundationdb"
  echo "  /usr/local/var/foundationdb"
  echo "  /var/foundationdb"
}

uninstall_fdb_linux_amd64() {
  if [[ "$ARCH" != "x86_64" ]]; then
    echo -e "${COLOR_RED}Unsupported architecture for this script on Linux: $ARCH (only x86_64/amd64 supported).${COLOR_OFF}"
    exit 1
  fi

  need_sudo

  if ! is_command_exists apt; then
    echo -e "${COLOR_RED}Error: This Linux uninstaller supports Debian/Ubuntu (apt) only.${COLOR_OFF}"
    exit 1
  fi

  echo -e "${COLOR_YELLOW}Uninstalling FoundationDB on Linux (apt)...${COLOR_OFF}"

  # Stop service if present
  if is_command_exists systemctl && pidof systemd >/dev/null 2>&1; then
    sudo systemctl stop foundationdb.service 2>/dev/null || sudo systemctl stop foundationdb 2>/dev/null || true
    sudo systemctl disable foundationdb.service 2>/dev/null || sudo systemctl disable foundationdb 2>/dev/null || true
  fi

  # Remove packages
  if dpkg -s foundationdb-server >/dev/null 2>&1 || dpkg -s foundationdb-clients >/dev/null 2>&1; then
    sudo apt remove -y foundationdb-server foundationdb-clients
    # purge configs too 
    sudo apt purge -y foundationdb-server foundationdb-clients || true
    sudo apt autoremove -y || true
    echo -e "${COLOR_GREEN}Linux uninstall completed.${COLOR_OFF}"
  else
    echo -e "${COLOR_YELLOW}FoundationDB packages not found via dpkg; nothing to uninstall.${COLOR_OFF}"
  fi

  echo -e "${COLOR_YELLOW}If you also want to remove data/config, check:${COLOR_OFF}"
  echo "  /etc/foundationdb"
  echo "  /var/lib/foundationdb"
  echo "  /var/log/foundationdb"
}

do_install() {
  if is_command_exists fdbcli; then
    echo -e "${COLOR_YELLOW}FoundationDB appears to be already installed:${COLOR_OFF}"
    fdbcli --version || true
    if [[ "$PLATFORM" == Darwin* ]]; then
      export_macos_link_env
    fi
    configure_fdb
    exit 0
  fi

  case "$PLATFORM" in
    Darwin*)
      echo -e "${COLOR_GREEN}FoundationDB is not installed. Setting it up for macOS arm64...${COLOR_OFF}"
      install_fdb_macos_arm64
      ;;
    Linux*)
      echo -e "${COLOR_GREEN}FoundationDB is not installed. Setting it up for Linux amd64...${COLOR_OFF}"
      install_fdb_linux_amd64
      ;;
    *)
      echo -e "${COLOR_RED}Error: Unsupported platform: $PLATFORM. Only macOS and Linux are supported.${COLOR_OFF}"
      exit 1
      ;;
  esac
}

do_uninstall() {
  case "$PLATFORM" in
    Darwin*)
      uninstall_fdb_macos_arm64
      ;;
    Linux*)
      uninstall_fdb_linux_amd64
      ;;
    *)
      echo -e "${COLOR_RED}Error: Unsupported platform: $PLATFORM. Only macOS and Linux are supported.${COLOR_OFF}"
      exit 1
      ;;
  esac
}

main() {
  local action="${1:-install}"
  case "$action" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
    docker)    shift; do_docker "${1:-start}" ;;
    help|-h|--help) usage ;;
    *)
      echo -e "${COLOR_RED}Unknown action: $action${COLOR_OFF}"
      usage
      exit 1
      ;;
  esac
}

main "$@"
