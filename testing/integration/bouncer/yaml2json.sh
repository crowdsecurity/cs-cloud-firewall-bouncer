#!/usr/bin/env bash
temp_dir=$(mktemp -d)
for f in expectations/*.yaml; do
    filename=$(basename $f .yaml)
    cat $f | yq . > "$temp_dir/$filename.json"
done
jq -s '. | flatten' $temp_dir/*.json > expectations/output/mocks.json