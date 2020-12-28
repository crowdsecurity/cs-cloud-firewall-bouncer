#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/cs-cloud-firewall-bouncer"
BIN_PATH="./cs-cloud-firewall-bouncer"
CONFIG_DIR="/etc/crowdsec/cs-cloud-firewall-bouncer/"
SYSTEMD_PATH_FILE="/etc/systemd/system/cs-cloud-firewall-bouncer.service"
API_URL=""
API_KEY=""
GCP_DISABLED=true
GCP_PROJECT_ID=""
GCP_NETWORK_ID=""
AWS_DISABLED=true
AWS_REGION=""
AWS_FIREWALL_POLICY=""
AWS_CAPACITY=0
AWS_RULE_GROUP_PRIORITY=0
CLOUDARMOR_DISABLED=true
CLOUDARMOR_PROJECT_ID=""
CLOUDARMOR_POLICY=""
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

gen_providers_config() {
    read -rp "Do you want to add GCP as a provider? [Y/n] " -e response
    case $response in
    [Nn]* )
        echo "Disabling GCP"
    ;;
    * )
        gen_gcp_config
    ;;
    esac
    read -rp "Do you want to add AWS as a provider? [Y/n] " -e response
    case $response in
    [Nn]* )
        echo "Disabling AWS"
    ;;
    * )
        gen_aws_config
    ;;
    esac
    read -rp "Do you want to add Cloud Armor as a provider? [Y/n] " -e response
    case $response in
    [Nn]* )
        echo "Disabling Cloud Armor"
    ;;
    * )
        gen_cloudarmor_config
    ;;
    esac
    if [[ ${GCP_DISABLED} == "true" && ${AWS_DISABLED} == "true" && ${CLOUDARMOR_DISABLED} == "true" ]]; then
        echo "At least one provider should be configured"
        exit 1
    fi
    read -rp "Firewall rule name prefix: " -i $RULE_NAME_PREFIX -e RULE_NAME_PREFIX
}

gen_gcp_config() {
    read -rp "Google project ID: " -e GCP_PROJECT_ID
    read -rp "Network ID: " -e GCP_NETWORK_ID
    GCP_DISABLED=false
}
gen_aws_config() {
    read -rp "AWS region: " -e AWS_REGION
    read -rp "Firewall policy name: " -e AWS_FIREWALL_POLICY
    read -rp "Capacity (leave empty for 1000): " -e AWS_CAPACITY
    read -rp "Rule group priority (leave empty for 1): " -e AWS_RULE_GROUP_PRIORITY
    AWS_DISABLED=false
}
gen_cloudarmor_config() {
    read -rp "Cloud Armor project ID: " -e CLOUDARMOR_PROJECT_ID
    read -rp "Policy name: " -e CLOUDARMOR_POLICY
    CLOUDARMOR_DISABLED=false
}

install_bouncer() {
	install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
	mkdir -p "${CONFIG_DIR}"
	cp "./config/cs-cloud-firewall-bouncer.yaml" "${CONFIG_DIR}cs-cloud-firewall-bouncer.yaml"
	CFG=${CONFIG_DIR} BIN=${BIN_PATH_INSTALLED} envsubst < ./config/cs-cloud-firewall-bouncer.service > "${SYSTEMD_PATH_FILE}"
	systemctl daemon-reload
}

gen_config_file() {
    GCP_DISABLED=${GCP_DISABLED} GCP_PROJECT_ID=${GCP_PROJECT_ID} GCP_NETWORK_ID=${GCP_NETWORK_ID} \
    AWS_DISABLED=${AWS_DISABLED} AWS_REGION=${AWS_REGION} AWS_FIREWALL_POLICY=${AWS_FIREWALL_POLICY} AWS_CAPACITY=${AWS_CAPACITY} AWS_RULE_GROUP_PRIORITY=${AWS_RULE_GROUP_PRIORITY} \
    CLOUDARMOR_DISABLED=${CLOUDARMOR_DISABLED} CLOUDARMOR_PROJECT_ID=${CLOUDARMOR_PROJECT_ID} CLOUDARMOR_POLICY=${CLOUDARMOR_POLICY} \
    API_URL=${API_URL} API_KEY=${API_KEY} RULE_NAME_PREFIX=${RULE_NAME_PREFIX} envsubst < ./config/cs-cloud-firewall-bouncer.yaml > "${CONFIG_DIR}cs-cloud-firewall-bouncer.yaml"
}

if ! [ $(id -u) = 0 ]; then
    log_err "Please run the install script as root or with sudo"
    exit 1
fi
echo "Installing cs-cloud-firewall-bouncer"
install_bouncer
gen_lapi_config
gen_providers_config
gen_config_file
systemctl enable cs-cloud-firewall-bouncer.service
systemctl start cs-cloud-firewall-bouncer.service
echo "cs-cloud-firewall-bouncer service has been installed!"
