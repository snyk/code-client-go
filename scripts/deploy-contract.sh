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

gitCommitSHA=$(git rev-parse HEAD)

echo "Deploy contract with workspace-service..."
pact-broker record_deployment --pacticipant code-client-go --version "$gitCommitSHA" --environment production --broker-base-url "$brokerUrl" --broker-token "$brokerToken"
