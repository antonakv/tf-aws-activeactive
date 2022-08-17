#!/usr/bin/env bash

# Stop on any error
set -euo pipefail

function get_secret {
    local secret_id=$1
    /usr/bin/env aws secretsmanager get-secret-value --secret-id $secret_id --region ${region} | jq --raw-output '.SecretBinary,.SecretString | select(. != null)'
}

logpath="/home/ubuntu/install/tfeinstall.log" 
replicated_url="https://s3.amazonaws.com/replicated-airgap-work/replicated.tar.gz"

mkdir -p /home/ubuntu/install

echo "$(date +"%T_%F") Create TFE and replicated setting files" | tee -a $logpath

sudo echo "${tfe_settings}" | base64 --decode > /etc/ptfe-settings.json

sudo echo "${replicated_settings}" | base64 --decode > /etc/replicated.conf

echo "$(date +"%T_%F") Extract certificate, key, license from AWS Secretsmanager" | tee -a $logpath

cert_base64=$(get_secret ${cert_secret_id})

key_base64=$(get_secret ${key_secret_id})

license_base64=$(get_secret ${license_secret_id})

echo "$(date +"%T_%F") Write certificate, key, license" | tee -a $logpath

echo $cert_base64 | base64 --decode > /home/ubuntu/install/certificate.pem

echo $key_base64 | base64 --decode > /home/ubuntu/install/key.pem

echo $license_base64 | base64 --decode > /home/ubuntu/install/license.rli

sudo mkdir -p /etc/replicated

echo "$(date +"%T_%F") Downloading replicated" | tee -a $logpath

curl --output /etc/replicated/replicated.tar.gz "$replicated_url"

echo "$(date +"%T_%F") Extracting replicated" | tee -a $logpath

tar --directory /etc/replicated --extract --file /etc/replicated/replicated.tar.gz

echo "$(date +"%T_%F") Downloading TFE online" | tee -a $logpath

curl --noproxy '*' --create-dirs --output /etc/replicated/install.sh https://get.replicated.com/docker/terraformenterprise/active-active

chmod +x /etc/replicated/install.sh

cd /etc/replicated

ipaddr=$(hostname -I | awk '{print $1}')

echo "$(date +"%T_%F") Installing TFE online" | tee -a $logpath

sudo chown -R ubuntu: /home/ubuntu

/etc/replicated/install.sh \
    fast-timeouts \
    bypass-firewalld-warning \
    no-proxy \
    disable-replicated-ui \
    private-address=$ipaddr \
    public-address=$ipaddr \
    | tee -a $logpath

