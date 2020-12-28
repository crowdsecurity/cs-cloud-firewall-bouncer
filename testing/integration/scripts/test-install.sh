#!/usr/bin/env bash

apt-get update && apt-get install -y gettext-base

mkdir release
cp ./cs-cloud-firewall-bouncer release/
cp -R ./config release/
cp ./scripts/install.sh release/

pushd release || exit 1
    ./install.sh << EOF
n
http://crowdsec:8080
12345

my-project
default

us-east1
my-firewall-policy
200
1

my-project
cloudarmor-policy
crowdsec
EOF
popd || exit 1

diff /etc/crowdsec/cs-cloud-firewall-bouncer/cs-cloud-firewall-bouncer.yaml testing/integration/scripts/expected-config.yaml && \
echo "Install script test completed successfully"

