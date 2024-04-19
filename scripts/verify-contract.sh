#! /bin/bash

node -v
npm -v

# TODO: this or CircleCI SSH keys?
if [ -z "$GITHUB_PAT" ]
then
  echo "Missing environment variable: GITHUB_PAT"
  exit 1
fi
github_pat=$GITHUB_PAT
if [ -z "$PACT_BROKER_URL" ]
then
  echo "Missing environment variable: PACT_BROKER_URL"
  exit 1
fi
brokerUrl=$PACT_BROKER_URL

gitCommitSHA=$(git rev-parse HEAD)
gitBranch=$(git rev-parse --abbrev-ref HEAD)
pactUrl=${brokerUrl}pacts/provider/WorkspaceApi/consumer/code-client-go/version/${gitCommitSHA}

echo "Verifying Pact contracts against workspace-service..."
git clone https://"${github_pat}"@github.com/snyk/workspace-service.git
cd workspace-service
## temporary change to branch
git checkout feat/spike/pact-separate
npm install

WORKSPACE_SERVICE_AUTH_TOKEN=test-service-auth-token GIT_BRANCH=${gitBranch} PACT_URL=${pactUrl} npm run test:contract

cd ../
rm -rf workspace-service

