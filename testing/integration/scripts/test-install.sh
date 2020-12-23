#!/usr/bin/env bash
apt-get update && apt-get install -y curl gettext-base
mkdir /cs-cloud-firewall-bouncer && cd /cs-cloud-firewall-bouncer || exit 1
curl -LO https://github.com/fallard84/cs-cloud-firewall-bouncer/releases/download/v0.1.0/cs-cloud-firewall-bouncer.tgz && \
    tar xzvf cs-cloud-firewall-bouncer.tgz && \
    cd cs-cloud-firewall-bouncer-v*/ && \
    chmod +x install.sh
    
printf 'n\nhttp://crowdsec:8080\n12345\n\nmy-project\ndefault\n\nus-east1\nmy-firewall-policy\n200\n1\ncrowdsec\n' | ./install.sh
diff /etc/crowdsec/cs-cloud-firewall-bouncer/cs-cloud-firewall-bouncer.yaml testing/integration/scripts/expected-config.yaml && echo "Install script test completed successfully"

