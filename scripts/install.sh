#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/cs-cloud-firewall-bouncer"
BIN_PATH="./cs-cloud-firewall-bouncer"
CONFIG_DIR="/etc/crowdsec/cs-cloud-firewall-bouncer/"
SYSTEMD_PATH_FILE="/etc/systemd/system/cs-cloud-firewall-bouncer.service"
API_URL=""
API_KEY=""
GCP_PROJECT_ID=""
GCP_NETWORK_ID=""
RULE_NAME_PREFIX="crowdsec"

gen_lapi_config() {
    read -rp "Is the crowdsec local API running on this machine? [Y/n] " -e response
    case $response in
    [Nn]* )
        read -rp "Crowdsec local API hostname (e.g. http://localhost:8080/): " -e API_URL
        read -rp "Crowdsec local API key: " -e API_KEY
    ;;
    * )
        API_URL="http://localhost:8080/"
        SUFFIX=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8)
        API_KEY=$(cscli bouncers add cs-cloud-firewall-bouncer-${SUFFIX} -o raw)
    ;;
    esac
}

gen_cloud_config() {
    read -rp "Google project ID: " -e GCP_PROJECT_ID
    read -rp "Network ID: " -e GCP_NETWORK_ID
    read -rp "Firewall rule name prefix: " -i $RULE_NAME_PREFIX -e RULE_NAME_PREFIX
}

install_bouncer() {
	install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
	mkdir -p "${CONFIG_DIR}"
	cp "./config/cs-cloud-firewall-bouncer.yaml" "${CONFIG_DIR}cs-cloud-firewall-bouncer.yaml"
	CFG=${CONFIG_DIR} BIN=${BIN_PATH_INSTALLED} envsubst < ./config/cs-cloud-firewall-bouncer.service > "${SYSTEMD_PATH_FILE}"
	systemctl daemon-reload
}

gen_config_file() {
    API_URL=${API_URL} API_KEY=${API_KEY} GCP_PROJECT_ID=${GCP_PROJECT_ID} GCP_NETWORK_ID=${GCP_NETWORK_ID} RULE_NAME_PREFIX=${RULE_NAME_PREFIX} envsubst < ./config/cs-cloud-firewall-bouncer.yaml > "${CONFIG_DIR}cs-cloud-firewall-bouncer.yaml"
}

if ! [ $(id -u) = 0 ]; then
    log_err "Please run the install script as root or with sudo"
    exit 1
fi
echo "Installing cs-cloud-firewall-bouncer"
install_bouncer
gen_lapi_config
gen_cloud_config
gen_config_file
systemctl enable cs-cloud-firewall-bouncer.service
systemctl start cs-cloud-firewall-bouncer.service
echo "cs-cloud-firewall-bouncer service has been installed!"
