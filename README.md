<p align="center">
<a href="https://github.com/crowdsecurity/crowdsec"><img src="https://github.com/crowdsecurity/crowdsec/raw/master/docs/assets/images/crowdsec_logo.png" alt="CrowdSec" title="CrowdSec" width="400" height="240" style="max-width:100%;"></a>
</p>
<p align="center">
<a href='https://github.com/fallard84/cs-cloud-firewall-bouncer/actions?query=workflow%3Abuild'><img src='https://github.com/fallard84/cs-cloud-firewall-bouncer/workflows/build/badge.svg' alt='Build Status' /></a>
<a href='https://github.com/fallard84/cs-cloud-firewall-bouncer/actions?query=branch%3Amain+workflow%3Atests'><img src='https://github.com/fallard84/cs-cloud-firewall-bouncer/workflows/tests/badge.svg?branch=main' alt='Tests Status' /></a>
<a href='https://coveralls.io/github/fallard84/cs-cloud-firewall-bouncer?branch=main'><img src='https://coveralls.io/repos/github/fallard84/cs-cloud-firewall-bouncer/badge.svg?branch=main' alt='Coverage Status' /></a>
<a href='https://goreportcard.com/report/github.com/fallard84/cs-cloud-firewall-bouncer'><img src='https://goreportcard.com/badge/github.com/fallard84/cs-cloud-firewall-bouncer' alt='Go Report Card' /></a>
<a href='https://opensource.org/licenses/MIT'><img src='https://img.shields.io/badge/License-MIT-yellow.svg' alt='License: MIT' /></a>

</p>

<p align="center">
&#x1F4DA; <a href="#installation-as-a-systemd-service">Documentation</a>
&#x1F4A0; <a href="https://hub.crowdsec.net">Hub</a>
&#128172; <a href="https://discourse.crowdsec.net">Discourse </a>
</p>

# CrowdSec Cloud Firewall Bouncer

Bouncer for cloud firewalls to use with [Crowdsec](https://github.com/crowdsecurity/crowdsec).

:warning: This is not an official Crowdsec bouncer.

The Cloud Firewall Bouncer will periodically fetch new and expired/removed decisions from the CrowdSec Local API and update cloud firewall rules accordingly.

Supported cloud providers:

- Google Cloud Platform (GCP) :heavy_check_mark:

:information_source: More cloud providers will be added shortly. See [todo](#todo)

## Usage with example

A complete step-by-step example of using the bouncer docker image with the GCP provider is available [here](docs/example.md).

## Using Docker

You can run this bouncer using the [docker image](https://hub.docker.com/r/fallard/cs-cloud-firewall-bouncer).

You will need to create the configuration file and mount it on the docker container. By default, the bouncer will look for the config at `/etc/crowdsec/config.d/config.yaml` but this can be overridden with the `CONFIG_PATH` environment variable.

## Installation (as a systemd service)

### With installer

First, download the latest [`cs-cloud-firewall-bouncer` release](https://github.com/fallard84/cs-cloud-firewall-bouncer/releases).

```sh
$ tar xzvf cs-cloud-firewall-bouncer.tgz
$ sudo ./install.sh
```

### From source

Run the following commands:

```bash
git clone https://github.com/fallard84/cs-cloud-firewall-bouncer.git
cd cs-cloud-firewall-bouncer/
make release
tar xzvf cs-cloud-firewall-bouncer.tgz
cd cs-cloud-firewall-bouncer-v*/
sudo ./install.sh
```

### Start

If your bouncer run on the same machine as your crowdsec local API, you can start the service directly since the `install.sh` took care of the configuration.

```sh
sudo systemctl start cs-cloud-firewall-bouncer
```

### Upgrade

If you already have `cs-cloud-firewall-bouncer` installed as a service, please download the [latest release](https://github.com/fallard84/cs-cloud-firewall-bouncer/releases) and run the following commands to upgrade it:

```bash
tar xzvf cs-cloud-firewall-bouncer.tgz
cd cs-cloud-firewall-bouncer-v*/
sudo ./upgrade.sh
```

## Configuration

Before starting the `cs-cloud-firewall-bouncer` service, please edit the configuration to add your cloud provider configuration, as well as the crowdsec local API url and key.
The default configuration file is located under : `/etc/crowdsec/cs-cloud-firewall-bouncer/`

```sh
$ vim /etc/crowdsec/cs-cloud-firewall-bouncer/cs-cloud-firewall-bouncer.yaml
```

```yaml
cloud_providers:
  gcp:
    project_id: gcp-project-id # optional if using application default credentials, will override project id of the application default credentials
    network: default # mandatory, this is the VPC network where the firewall rules will be created
rule_name_prefix: crowdsec # mandatory, this is the prefix for the firewall rule names to create/update
update_frequency: 10s
daemonize: true
log_mode: stdout
log_dir: log/
log_level: info
api_url: <API_URL> # when install, default is "localhost:8080"
api_key: <API_KEY> # Add your API key generated with `cscli bouncers add --name <bouncer_name>`
```

## Authentication

### GCP

Authentication to GCP is done through [Application Default Credentials](https://cloud.google.com/docs/authentication/production). If using a service account, the GCP project ID will be automatically determined (using the project ID of the service account) and does not have to be specified in the configuration. If the service account resides in a different project than the VPC network, the GCP project ID must be overridden in the configuration.

The service account will need the following permissions:

- compute.firewalls.create
- compute.firewalls.delete
- compute.firewalls.get
- compute.firewalls.list
- compute.firewalls.update
- compute.networks.updatePolicy

## Todo

- Add AWS Network Firewall as a provider
- Add Azure as a provider
- Add Google Cloud Armor as a provider
- Add AWS WAF as a provider
