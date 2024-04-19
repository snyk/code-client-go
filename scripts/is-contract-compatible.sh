#! /bin/bash

if [ -z "$PACT_BROKER_URL" ]
then
  echo "Missing environment variable: PACT_BROKER_URL"
  exit 1
fi
brokerUrl=$PACT_BROKER_URL
if  [ -z "$PACT_BROKER_TOKEN" ]
then
  echo "Missing environment variable: PACT_BROKER_TOKEN"
  exit 1
fi
brokerToken=$PACT_BROKER_TOKEN
consumerVersion=$(git rev-parse HEAD)

echo "Checking if we can deploy..."
pact-broker can-i-deploy --pacticipant code-client-go --version "${consumerVersion}" --broker-base-url "$brokerUrl" --broker-token "$brokerToken" --to-environment production --retry-while-unknown 0 --retry-interval 10