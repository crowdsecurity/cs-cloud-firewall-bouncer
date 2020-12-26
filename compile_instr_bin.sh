#!/usr/bin/env bash
go test . -tags testbincover -coverpkg=./... -c -o cs-cloud-firewall-bouncer_instr-bin -ldflags="-X github.com/fallard84/cs-cloud-firewall-bouncer.isTest=true"