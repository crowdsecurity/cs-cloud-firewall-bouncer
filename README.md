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

- Google Cloud Platform (GCP) Network Firewall:heavy_check_mark:
- Google Cloud Platform (GCP) Cloud Armor:heavy_check_mark:
- Amazon Web Services (AWS) Network Firewall :heavy_check_mark:

## Usage with example

A complete step-by-step example of using the bouncer docker image with the GCP provider is available [here](docs/example-gcp.md).

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
cloud_providers: # 1 or more provider needs to be specified
  gcp:
    project_id: gcp-project-id # optional if using application default credentials, will override project id of the application default credentials
    network: default # mandatory. This is the VPC network where the firewall rules will be created
    priority: 0 # optional, defaults to 0 (highest priority). Additional rules will be incremented by 1.
    max_rules: 10 # optional, defaults to 10. This is the maximum number of rules to create. One GCP network firewall rule can contain at most 256 source ranges. Using the default of 10 means 2560 source ranges at most can be created. A GCP project has a default quota of 100 rules across all VPC networks. See https://cloud.google.com/vpc/docs/quota for more info.
  aws:
    region: us-east-1 # mandatory
    firewall_policy: policy-name # mandatory, this is the firewall policy which will contain the rule group. The firewall policy must exist.
    capacity: 1000 # optional, defaults to 1000. This is the capacity of the stateless rule group that the bouncer will create. A capacity of 1000 signify that the rule will contain at most 1000 source ranges. AWS has a default quota of 10,000 stateless capacity per account per region. See https://docs.aws.amazon.com/network-firewall/latest/developerguide/quotas.html for more info. This capacity is only used when the rule is being created and will not be updated afterwards.
    priority: 1 # optional, defaults to 1 (highest priority). This is the priority of the rule group in the firewall policy.
  cloudarmor:
    project_id: gcp-project-id # optional if using application default credentials, will override project id of the application
    policy: test-policy # mandatory, this is the cloud armor policy which will contain the rules. The cloud armor policy must exist.
    priority: 0 # optional, defaults to 0 (highest priority). Additional rules will be incremented by 1.
    max_rules: 100 # optional, defaults to 100. This is the maximum number of rules to create. One cloud armor rule can contain at most 10 source ranges. A GCP project has a default quota of 200 rules across all security policies. Using the default of 100 means 1000 source ranges at most can be created. See https://cloud.google.com/armor/quotas for more info.
rule_name_prefix: crowdsec # mandatory, this is the prefix for the firewall rule name(s) to create/update
update_frequency: 10s
daemonize: true
log_mode: stdout
log_dir: log/
log_level: info
api_url: <API_URL> # when install, default is "localhost:8080"
api_key: <API_KEY> # Add your API key generated with `cscli bouncers add --name <bouncer_name>`
```

### Rule name prefix requirements

The rule name prefix be 1-44 characters long and match the regular expression `^(?:[a-z](?:[-a-z0-9]{0,43})?)\$`. The first character
must be a lowercase letter, and all following characters must be a dash, lowercase letter, or
digit. The name cannot contain two consecutive dash ('-') characters.

## Authentication

### GCP

Authentication to GCP is done through [Application Default Credentials](https://cloud.google.com/docs/authentication/production). If using a service account, the GCP project ID will be automatically determined (using the project ID of the service account) and does not have to be specified in the configuration. If the service account resides in a different project than the VPC network/Cloud Armor policy, the GCP project ID must be overridden in the configuration.

#### Network Firewall

The service account will need the following permissions:

- compute.firewalls.create
- compute.firewalls.delete
- compute.firewalls.get
- compute.firewalls.list
- compute.firewalls.update
- compute.networks.updatePolicy

#### Cloud Armor

The service account will need the following permissions:

- compute.securityPolicies.get
- compute.securityPolicies.update

The managed role `roles/compute.securityAdmin` already provides these permissions.

### AWS

Authentication to AWS is done through the [default credential provider chain](https://docs.aws.amazon.com/sdk-for-go/api/aws/defaults/#CredChain).

The user account will need the following permissions:

- ListFirewallPolicies
- ListRuleGroups
- DescribeFirewallPolicy
- DescribeRuleGroup
- CreateRuleGroup
- DeleteRuleGroup
- UpdateFirewallPolicy
- UpdateRuleGroup

The managed role `NetworkFirewallManager` already provides these permissions.

## Todo

- Add Azure as a provider
- Add AWS WAF as a provider
