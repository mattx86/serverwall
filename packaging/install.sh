#!/usr/bin/env bash
set -euo pipefail

# ─── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="/opt/serverwall"
BIN_DIR="${BASE_DIR}/bin"
ETC_DIR="${BASE_DIR}/etc"
RUN_DIR="${BASE_DIR}/run"
LOG_DIR="${BASE_DIR}/var/log"
LIB_DIR="${BASE_DIR}/var/lib"
SPOOL_DIR="${BASE_DIR}/var/spool"
SYSTEMD_DIR="/etc/systemd/system"
SW_USER="serverwall"
SW_GROUP="serverwall"

# ─── Root check ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "Error: install.sh must be run as root." >&2
    echo "       Try: sudo bash install.sh" >&2
    exit 1
fi

echo "Installing ServerWall..."
echo ""

# ─── System user and group ────────────────────────────────────────────────────
if ! getent group "$SW_GROUP" > /dev/null 2>&1; then
    groupadd --system "$SW_GROUP"
    echo "[+] Created group: $SW_GROUP"
fi

if ! getent passwd "$SW_USER" > /dev/null 2>&1; then
    useradd --system \
            --gid "$SW_GROUP" \
            --no-create-home \
            --shell /sbin/nologin \
            "$SW_USER"
    echo "[+] Created user: $SW_USER"
fi

# ─── Directories ──────────────────────────────────────────────────────────────
install -d -m 755 -o root      -g root      "$BASE_DIR"
install -d -m 750 -o root      -g "$SW_GROUP" "$BIN_DIR"
install -d -m 750 -o root      -g "$SW_GROUP" "$ETC_DIR"
install -d -m 750 -o root      -g "$SW_GROUP" "${ETC_DIR}/certs"
install -d -m 750 -o root      -g "$SW_GROUP" "${ETC_DIR}/dkim"
install -d -m 750 -o root      -g "$SW_GROUP" "${ETC_DIR}/acme"
install -d -m 755 -o "$SW_USER" -g "$SW_GROUP" "$RUN_DIR"
install -d -m 755 -o "$SW_USER" -g "$SW_GROUP" "$LOG_DIR"
install -d -m 755 -o "$SW_USER" -g "$SW_GROUP" "$LIB_DIR"
install -d -m 755 -o "$SW_USER" -g "$SW_GROUP" "$SPOOL_DIR"
echo "[+] Created runtime directories under ${BASE_DIR}"

# ─── Binaries ─────────────────────────────────────────────────────────────────
install -m 755 -o root -g "$SW_GROUP" "${SCRIPT_DIR}/bin/serverwall"        "${BIN_DIR}/serverwall"
install -m 755 -o root -g "$SW_GROUP" "${SCRIPT_DIR}/bin/serverwall-webui"  "${BIN_DIR}/serverwall-webui"
install -m 755 -o root -g "$SW_GROUP" "${SCRIPT_DIR}/bin/serverwallctl"     "${BIN_DIR}/serverwallctl"
echo "[+] Installed binaries to ${BIN_DIR}"

# ─── Systemd services ─────────────────────────────────────────────────────────
install -m 644 "${SCRIPT_DIR}/systemd/serverwall.service"       "${SYSTEMD_DIR}/serverwall.service"
install -m 644 "${SCRIPT_DIR}/systemd/serverwall-webui.service" "${SYSTEMD_DIR}/serverwall-webui.service"
echo "[+] Installed systemd unit files"

systemctl daemon-reload
systemctl enable serverwall serverwall-webui
echo "[+] Services enabled (serverwall + serverwall-webui)"

# ─── First-run init ───────────────────────────────────────────────────────────
echo ""
echo "Running first-time initialisation..."
"${BIN_DIR}/serverwall" --init

# ─── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo "ServerWall installed successfully."
echo ""
echo "  Start:   systemctl start serverwall"
echo "  Status:  systemctl status serverwall serverwall-webui"
echo "  Logs:    journalctl -u serverwall -f"
echo ""
