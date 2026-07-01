#!/bin/bash

set -e

ssl=${ssl:-false}
private_key=${private_key:-tls.key}
certificate_request=${certificate_request:-tls.csr}
certificate=${certificate:-tls.crt}

# Generate certificate
if [[ $ssl == "true" ]]; then
  url=${url:-"https://localhost"}

  mkdir -p data/certs
  pushd data/certs

  openssl genrsa -out ${private_key} 2048
  openssl req \
    -new \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" \
    -key ${private_key} \
    -out ${certificate_request}
  openssl x509 -req -days 365 -in ${certificate_request} -signkey ${private_key} -out ${certificate}
  openssl dhparam -out dhparam.pem 2048
  chmod 400 ${private_key}

  popd
else
  url=${url:-"http://localhost"}
fi

# Check if the yml exists
if [[ ! -f $config ]]; then
  echo "File $config doesn't exist!"
  exit 1
fi

trap 'docker compose -p ds -f $config down' EXIT

# Run test environment
docker compose -p ds -f $config up -d

wakeup_timeout=300

# Get documentserver healthcheck status
echo "Wait for service wake up"
for (( elapsed=0; elapsed<=wakeup_timeout; elapsed+=10 )); do
  if healthcheck_res=$(wget --no-check-certificate -qO - ${url}/healthcheck); then
    if [[ $healthcheck_res == "true" ]]; then
      break
    fi
  fi

  sleep 10
done

# Fail if it isn't true
if [[ $healthcheck_res == "true" ]]; then
  echo "Healthcheck passed."
else
  echo "Healthcheck failed!"
  docker compose -p ds -f $config logs --no-color
  exit 1
fi
