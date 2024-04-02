#!/usr/bin/env bash

if [ -z "${GITHUB_PAT}" ]; then
  echo "Could not run the script. The GITHUB_PAT environment variable must be set to a valid Personal Access Token."
  exit 1
fi

WORKSPACE_API_VERSION="2024-03-12"
WORKSPACE_COMMIT_SHA="cfd737cd917ab2c63840bd112d9eb2c9a9c101f6"

mkdir -p ./internal/workspace/${WORKSPACE_API_VERSION}

# Download the Common spec
set -e
curl -s https://${GITHUB_PAT}@raw.githubusercontent.com/snyk/sweater-comb/common-model-v1/components/common.yaml > ./internal/workspace/${WORKSPACE_API_VERSION}/common/common.yaml
set +e
yq -i e '{"components": .}' ./internal/workspace/${WORKSPACE_API_VERSION}/common/common.yaml
sed -i '' "s@#/schemas/@#/components/schemas/@g" ./internal/workspace/${WORKSPACE_API_VERSION}/common/common.yaml
sed -i '' "s@#/headers/@#/components/headers/@g" ./internal/workspace/${WORKSPACE_API_VERSION}/common/common.yaml

# Download the Links model spec for the Workspace API
set -e
curl -s https://${GITHUB_PAT}@raw.githubusercontent.com/snyk/workspace-service/${WORKSPACE_COMMIT_SHA}/src/rest/api/hidden/models/links.yaml > ./internal/workspace/${WORKSPACE_API_VERSION}/links/links.yaml
set +e
yq -i e  '{"components": .}' ./internal/workspace/${WORKSPACE_API_VERSION}/links/links.yaml
sed -i '' "s@#/schemas@#/components/schemas@g" ./internal/workspace/${WORKSPACE_API_VERSION}/links/links.yaml

# Download the Org parameter spec for the Workspace API
set -e
curl -s https://${GITHUB_PAT}@raw.githubusercontent.com/snyk/workspace-service/${WORKSPACE_COMMIT_SHA}/src/rest/api/hidden/parameters/orgs.yaml > ./internal/workspace/${WORKSPACE_API_VERSION}/parameters/orgs.yaml
set +e
yq -i e  '{"components": {"parameters": .}}' ./internal/workspace/${WORKSPACE_API_VERSION}/parameters/orgs.yaml

# Download the Request ID parameter spec for the Workspace API
set -e
curl -s https://${GITHUB_PAT}@raw.githubusercontent.com/snyk/workspace-service/${WORKSPACE_COMMIT_SHA}/src/rest/api/hidden/parameters/request-id.yaml > ./internal/workspace/${WORKSPACE_API_VERSION}/parameters/request-id.yaml
set +e
yq -i e  '{"components": {"parameters": .}}' ./internal/workspace/${WORKSPACE_API_VERSION}/parameters/request-id.yaml

# Download the User Agent parameter spec for the Workspace API
set -e
curl -s https://${GITHUB_PAT}@raw.githubusercontent.com/snyk/workspace-service/${WORKSPACE_COMMIT_SHA}/src/rest/api/hidden/parameters/user-agent.yaml > ./internal/workspace/${WORKSPACE_API_VERSION}/parameters/user-agent.yaml
set +e
yq -i e  '{"components": {"parameters": .}}' ./internal/workspace/${WORKSPACE_API_VERSION}/parameters/user-agent.yaml

# Download the Content Type parameter spec for the Workspace API
set -e
curl -s https://${GITHUB_PAT}@raw.githubusercontent.com/snyk/workspace-service/${WORKSPACE_COMMIT_SHA}/src/rest/api/hidden/parameters/content-type.yaml > ./internal/workspace/${WORKSPACE_API_VERSION}/parameters/content-type.yaml
set +e
yq -i e  '{"components": {"parameters": .}}' ./internal/workspace/${WORKSPACE_API_VERSION}/parameters/content-type.yaml

# Download the Workspace model spec for the Workspace API
set -e
curl -s https://${GITHUB_PAT}@raw.githubusercontent.com/snyk/workspace-service/${WORKSPACE_COMMIT_SHA}/src/rest/api/hidden/resources/workspaces/${WORKSPACE_API_VERSION}/models/workspaces.yaml > ./internal/workspace/${WORKSPACE_API_VERSION}/workspaces/workspaces.yaml
set +e
yq -i e  '{"components": .}' ./internal/workspace/${WORKSPACE_API_VERSION}/workspaces/workspaces.yaml
sed -i '' "s@https://raw.githubusercontent.com/snyk/sweater-comb/common-model-v1/components/common.yaml#@../common/common.yaml#/components@g" ./internal/workspace/${WORKSPACE_API_VERSION}/workspaces/workspaces.yaml
sed -i '' "s@../../../../models/links.yaml#@../links/links.yaml#/components@g" ./internal/workspace/${WORKSPACE_API_VERSION}/workspaces/workspaces.yaml

# Download the Workspace API spec
set -e
curl -s https://${GITHUB_PAT}@raw.githubusercontent.com/snyk/workspace-service/${WORKSPACE_COMMIT_SHA}/src/rest/api/hidden/resources/workspaces/${WORKSPACE_API_VERSION}/spec.yaml > ./internal/workspace/${WORKSPACE_API_VERSION}/spec.yaml
set +e
sed -i '' "s@./models/workspaces.yaml#/schemas@./workspaces/workspaces.yaml#/components/schemas@g" ./internal/workspace/${WORKSPACE_API_VERSION}/spec.yaml
sed -i '' "s@#/components/x-snyk-common@./common/common.yaml#/components@g" ./internal/workspace/${WORKSPACE_API_VERSION}/spec.yaml
sed -i '' "s@../../../parameters/orgs.yaml#@./parameters/orgs.yaml#/components/parameters@g" ./internal/workspace/${WORKSPACE_API_VERSION}/spec.yaml
sed -i '' "s@../../../parameters/request-id.yaml#@./parameters/request-id.yaml#/components/parameters@g" ./internal/workspace/${WORKSPACE_API_VERSION}/spec.yaml
sed -i '' "s@../../../parameters/user-agent.yaml#@./parameters/user-agent.yaml#/components/parameters@g" ./internal/workspace/${WORKSPACE_API_VERSION}/spec.yaml
sed -i '' "s@../../../parameters/content-type.yaml#@./parameters/content-type.yaml#/components/parameters@g" ./internal/workspace/${WORKSPACE_API_VERSION}/spec.yaml