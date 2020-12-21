#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/cs-cloud-firewall-bouncer"
BIN_PATH="./cs-cloud-firewall-bouncer"


upgrade_bin() {
    rm "${BIN_PATH_INSTALLED}" || (echo "cs-cloud-firewall-bouncer is not installed, exiting." && exit 1)
    install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
}


if ! [ $(id -u) = 0 ]; then
    log_err "Please run the upgrade script as root or with sudo"
    exit 1
fi

systemctl stop cs-cloud-firewall-bouncer
upgrade_bin
systemctl start cs-cloud-firewall-bouncer
echo "cs-cloud-firewall-bouncer upgraded successfully."