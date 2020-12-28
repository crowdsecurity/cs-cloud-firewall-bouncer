#!/usr/bin/env bash
set -e

function yaml2json {
    echo "Converting yaml to json"
    temp_dir=$(mktemp -d)
    for f in expectations/*.yaml; do
        filename=$(basename $f .yaml)
        cat $f | yq eval -j > "$temp_dir/$filename.json"
    done
    mkdir -p expectations/output
    jq -s '. | flatten' $temp_dir/*.json > expectations/output/mocks.json
}

root_dir=${PWD}
pushd testing/integration/bouncer || exit 1
    yaml2json
    echo "Starting mock server"
    docker-compose up -d
    echo "Waiting for mock server to be up"
    count=0
    until $(curl --output /dev/null --silent --fail http://localhost:1080/healthz); do
        if [[ $count -ge 5 ]]; then
            echo "Something went wrong starting the mock server:"
            docker-compose logs
            docker-compose down
            exit 1
        fi
        printf '.'
        sleep 2
        count=$((count+1))
    done
    printf "\nStarting test\n"
    GOOGLE_APPLICATION_CREDENTIALS="${PWD}/gcp-sa.json" AWS_ACCESS_KEY_ID=dummy-id AWS_SECRET_ACCESS_KEY=dummy-secret go test ${root_dir}/main_test.go -v -bin-c ${PWD}/config.yaml &
    echo "Waiting 15 sec, then stopping process"
    sleep 30
    echo "Stopping process"
    ps -ewo pid,cmd | grep "cs-cloud-firewall-bouncer_instr-bin" |  grep -v "grep" | awk '{ print $1 }' | xargs -I{} kill -SIGTERM {}
    echo "Stopping mock server"
    docker-compose down
popd || exit 1
cat log/*.log
cat log/*.log | (! grep -e "error" -e "fatal" -e "panic")