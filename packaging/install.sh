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
GEOIP_DIR="${BASE_DIR}/lib/geoip"
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
install -d -m 755 -o root       -g "$SW_GROUP" "${BASE_DIR}/lib"
install -d -m 755 -o root       -g "$SW_GROUP" "$GEOIP_DIR"
echo "[+] Created runtime directories under ${BASE_DIR}"

# ─── Binaries ─────────────────────────────────────────────────────────────────
install -m 755 -o root -g "$SW_GROUP" "${SCRIPT_DIR}/bin/serverwall"        "${BIN_DIR}/serverwall"
install -m 755 -o root -g "$SW_GROUP" "${SCRIPT_DIR}/bin/serverwall-webui"  "${BIN_DIR}/serverwall-webui"
install -m 755 -o root -g "$SW_GROUP" "${SCRIPT_DIR}/bin/serverwallctl"     "${BIN_DIR}/serverwallctl"
echo "[+] Installed binaries to ${BIN_DIR}"

# ─── GeoIP database ───────────────────────────────────────────────────────────
if [[ -f "${SCRIPT_DIR}/geoip/dbip-country-lite.mmdb" ]]; then
    install -m 644 -o root -g "$SW_GROUP" \
        "${SCRIPT_DIR}/geoip/dbip-country-lite.mmdb" \
        "${GEOIP_DIR}/dbip-country-lite.mmdb"
    echo "[+] Installed DB-IP country database to ${GEOIP_DIR}"
    echo "    Attribution: DB-IP.com (CC BY 4.0) — see THIRD_PARTY_NOTICES"
fi

# ─── Systemd services ─────────────────────────────────────────────────────────
install -m 644 "${SCRIPT_DIR}/systemd/serverwall.service"       "${SYSTEMD_DIR}/serverwall.service"
install -m 644 "${SCRIPT_DIR}/systemd/serverwall-webui.service" "${SYSTEMD_DIR}/serverwall-webui.service"
echo "[+] Installed systemd unit files"

systemctl daemon-reload

# ─── First-run init ───────────────────────────────────────────────────────────
echo ""
echo "Running first-time initialisation..."
"${BIN_DIR}/serverwall" --init

# ─── Fix ownership so the serverwall user can access all files ────────────────
chown -R serverwall: /opt/serverwall
echo "[+] Set ownership of ${BASE_DIR} to serverwall"

# ─── Enable and start services ────────────────────────────────────────────────
echo ""
systemctl enable serverwall serverwall-webui
echo "[+] Services enabled (serverwall + serverwall-webui)"

systemctl start serverwall
echo "[+] serverwall started"

systemctl start serverwall-webui
echo "[+] serverwall-webui started"

# ─── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo "ServerWall installed and running."
echo ""
echo "  Status:  systemctl status serverwall serverwall-webui"
echo "  Logs:    journalctl -u serverwall -f"
echo "  Web UI:  https://$(hostname):8443"
echo ""
