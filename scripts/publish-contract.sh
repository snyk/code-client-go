#! /bin/bash

if [ -z "$PACT_BROKER_BASE_URL" ]
then
  echo "Missing environment variable: PACT_BROKER_BASE_URL"
  exit 1
fi
brokerUrl=$PACT_BROKER_URL
if  [ -z "$PACT_BROKER_TOKEN" ]
then
  echo "Missing environment variable: PACT_BROKER_TOKEN"
  exit 1
fi
gitCommitSHA=$(git rev-parse HEAD)
gitBranch=$(git rev-parse --abbrev-ref HEAD)

pact-broker publish ./internal/workspace/2024-05-14/pacts/code-client-go-workspace-service.json --consumer-app-version "$gitCommitSHA" --branch="$gitBranch"