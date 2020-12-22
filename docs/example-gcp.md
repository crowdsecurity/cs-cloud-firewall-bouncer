# How to use this bouncer in Docker

## Example with GCP

The following example shows how to run the bouncer in a separate container from the crowdsec local api. This is because the bouncer container does not contain the crowdsec service. The bouncer will update GCP firewall rules.

### 1. Create GCP service account

First, let's create a GCP service account with a custom role that grants the required permissions. Replace `PROJECT_ID` with your GCP project.

```shell
export PROJECT_ID=#put your project ID
gcloud iam service-accounts create crowdsec --project=$PROJECT_ID
gcloud iam roles create FirewallManager --project=$PROJECT_ID \
 --permissions=compute.firewalls.create,compute.firewalls.delete,compute.firewalls.get,compute.firewalls.list,compute.firewalls.update,compute.networks.updatePolicy
gcloud projects add-iam-policy-binding $PROJECT_ID \
 --member="serviceAccount:crowdsec@$PROJECT_ID.iam.gserviceaccount.com" \
 --role="projects/$PROJECT_ID/roles/FirewallManager"
```

Now we can create a service account key that we will use in our bouncer container to authenticate to GCP.

```shell
gcloud iam service-accounts keys create gcp-sa.json \
 --iam-account=crowdsec@$PROJECT_ID.iam.gserviceaccount.com
```

### 2. Start the crowdsec service

In order for the containers to be able to communicate, we need to first create a docker network

```shell
docker network create --driver bridge crowdsec
```

Then we create the following files on the host so we can persist its data in case the docker container is removed:

```shell
touch database.db local_api_credentials.yaml
docker run -d --rm --network crowdsec \
 -v $(pwd)/local_api_credentials.yaml:/etc/crowdsec/local_api_credentials.yaml \
 -v $(pwd)/database.db:/var/lib/crowdsec/data/crowdsec.db \
 --name crowdsec crowdsecurity/crowdsec
```

We need to create a new bouncer using cscli

```shell
docker exec crowdsec cscli bouncers add cloud-firewall-bouncer
```

You should get an output similar to this:

```shell
Api key for 'cloud-firewall-bouncer':

   144676c934bd52210f80e37ec7925737

Please keep this key since you will not be able to retrive it!
```

### 3. Run the bouncer container

You should now have all data to create the bouncer configuration. Assuming I am using GCP service account credentials and I want to create firewall rules on the default network, you would have the following configuration:

config-bouncer.yaml:

```yaml
cloud_providers:
  gcp:
    network: default
rule_name_prefix: crowdsec
update_frequency: 10s
daemonize: false
log_mode: stdout
log_dir: log/
log_level: info
api_url: http://crowdsec:8080/
api_key: 144676c934bd52210f80e37ec7925737
```

We can now run the bouncer container

```shell
docker run -it --rm --network crowdsec \
 -v $(pwd)/config-bouncer.yaml:/etc/crowdsec/config.d/config.yaml \
 -v $(pwd)/gcp-sa.json:/auth/gcp-sa.json \
 -e GOOGLE_APPLICATION_CREDENTIALS=/auth/gcp-sa.json \
 fallard/cs-cloud-firewall-bouncer
```

You can now see the bouncer in action by manually adding a decisions using cscli

```shell
docker exec crowdsec cscli decisions add -i 1.2.3.4
docker exec crowdsec cscli decisions add -i 1.2.3.5
docker exec crowdsec cscli decisions add -i 1.2.3.6
docker exec crowdsec cscli decisions add -i 1.2.3.7
```

And view the generated firewall rule

```shell
gcloud compute firewall-rules list --project $PROJECT_ID \
 --filter='name~crowdsec' --format="table(
                name,
                network,
                direction,
                priority,
                sourceRanges.list():label=SRC_RANGES,
                denied[].map().firewall_rule().list():label=DENY
            )"
```
