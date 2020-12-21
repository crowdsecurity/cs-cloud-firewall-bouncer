#!/usr/bin/env bash

SYSTEMD_PATH_FILE="/etc/systemd/system/cs-cloud-firewall-bouncer.service"
LOG_FILE="/var/log/cs-cloud-firewall-bouncer.log"
CONFIG_DIR="/etc/crowdsec/cs-cloud-firewall-bouncer/"
BIN_PATH_INSTALLED="/usr/local/bin/cs-cloud-firewall-bouncer"

uninstall() {
	systemctl stop cs-cloud-firewall-bouncer
	rm -rf "${CONFIG_DIR}"
	rm -f "${SYSTEMD_PATH_FILE}"
	rm -f "${BIN_PATH_INSTALLED}"
	rm -f "${LOG_FILE}"
}

uninstall

echo "cs-cloud-firewall-bouncer uninstall successfully"