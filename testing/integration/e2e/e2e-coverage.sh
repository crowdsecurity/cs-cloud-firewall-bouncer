#!/usr/bin/env bash
set -e

root_dir=${PWD}
rm -f e2e_coverage.out
pushd testing/integration/e2e || exit 1
    echo "Starting mock server"
    docker-compose up -d
    echo "Waiting for mock server to be up"
    until $(curl --output /dev/null --silent --fail http://localhost:1080/healthz); do
        printf '.'
        sleep 2
    done
    printf "\nStarting e2e test\n"
    GOOGLE_APPLICATION_CREDENTIALS="${PWD}/gcp-sa.json" go test ${root_dir}/main_test.go -v -bin-c ${PWD}/config.yaml &
    echo "Waiting 15 sec, then stopping process"
    sleep 30
    echo "Stopping process"
    ps -ewo pid,cmd | grep "cs-cloud-firewall-bouncer_instr-bin" |  grep -v "grep" | awk '{ print $1 }' | xargs -I{} kill -SIGTERM {}
    echo "Stopping mock server"
    docker-compose down
popd || exit 1
cat log/*.log
cat log/*.log | grep -e "error" -e "fatal" -e "panic" && exit 1