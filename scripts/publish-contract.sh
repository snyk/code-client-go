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

echo "Publishing Pact contracts..."
pact-broker publish internal/workspace/2024-03-12/pacts/code-client-go-workspaceapi.json --consumer-app-version "$gitCommitSHA" --tag-with-git-branch --broker-base-url "$brokerUrl" --broker-token "$brokerToken"
