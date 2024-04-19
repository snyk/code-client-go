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

#docker run -v $(pwd)/internal/workspace/2024-05-14/pacts/code-client-go-workspace-service.json:/code-client-go-workspace-service.json --rm \
#  -e PACT_BROKER_BASE_URL \
#  -e PACT_BROKER_TOKEN \
#  pactfoundation/pact-cli:latest \
#  publish \
#  /code-client-go-workspace-service.json \
#  --branch="$gitBranch" \
#  --consumer-app-version "$gitCommitSHA"

docker run --rm \
 -w ${PWD} \
 -v ${PWD}:${PWD} \
 -e PACT_BROKER_BASE_URL \
 -e PACT_BROKER_TOKEN \
  pactfoundation/pact-cli:latest \
  publish \
  ${PWD}/internal/workspace/2024-05-14/pacts/code-client-go-workspace-service.json \
  --branch="$gitBranch" \
  --consumer-app-version "$gitCommitSHA"
