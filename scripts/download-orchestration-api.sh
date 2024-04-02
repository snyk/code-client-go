#!/usr/bin/env bash

if [ -z "${GITHUB_PAT}" ]; then
  echo "Could not run the script. The GITHUB_PAT environment variable must be set to a valid Personal Access Token."
  exit 1
fi

ORCHESTRATION_API_VERSION="2024-02-16"
ORCHESTRATION_COMMIT_SHA="c6a338190fa7260f8154d386589c5e42ea9c7479"

mkdir -p ./internal/orchestration/${ORCHESTRATION_API_VERSION}

# Download the Common spec
set -e
curl -s https://${GITHUB_PAT}@raw.githubusercontent.com/snyk/sweater-comb/common-model-v1/components/common.yaml > ./internal/orchestration/${ORCHESTRATION_API_VERSION}/common/common.yaml
set +e
yq -i e '{"components": .}' ./internal/orchestration/${ORCHESTRATION_API_VERSION}/common/common.yaml
sed -i '' "s@#/schemas/@#/components/schemas/@g" ./internal/orchestration/${ORCHESTRATION_API_VERSION}/common/common.yaml
sed -i '' "s@#/headers/@#/components/headers/@g" ./internal/orchestration/${ORCHESTRATION_API_VERSION}/common/common.yaml

## Download the Links model spec for the orchestration API
#set -e
#curl -s https://${GITHUB_PAT}@raw.githubusercontent.com/snyk/orchestration-service/${ORCHESTRATION_COMMIT_SHA}/src/rest/api/hidden/models/links.yaml > ./internal/orchestration/${ORCHESTRATION_API_VERSION}/links/links.yaml
#set +e
#yq -i e  '{"components": .}' ./internal/orchestration/${ORCHESTRATION_API_VERSION}/links/links.yaml
#sed -i '' "s@#/schemas@#/components/schemas@g" ./internal/orchestration/${ORCHESTRATION_API_VERSION}/links/links.yaml

# Download the Org parameter spec for the orchestration API
set -e
curl -s https://${GITHUB_PAT}@raw.githubusercontent.com/snyk/orchestration-service/${ORCHESTRATION_COMMIT_SHA}/src/rest/parameters/orgs.yaml > ./internal/orchestration/${ORCHESTRATION_API_VERSION}/parameters/orgs.yaml
set +e
yq -i e  '{"components": {"parameters": .}}' ./internal/orchestration/${ORCHESTRATION_API_VERSION}/parameters/orgs.yaml

# Download the Scan parameter spec for the orchestration API
set -e
curl -s https://${GITHUB_PAT}@raw.githubusercontent.com/snyk/orchestration-service/${ORCHESTRATION_COMMIT_SHA}/src/rest/parameters/scans.yaml > ./internal/orchestration/${ORCHESTRATION_API_VERSION}/parameters/scans.yaml
set +e
yq -i e  '{"components": {"parameters": .}}' ./internal/orchestration/${ORCHESTRATION_API_VERSION}/parameters/scans.yaml

## Download the Content Type parameter spec for the orchestration API
#set -e
#curl -s https://${GITHUB_PAT}@raw.githubusercontent.com/snyk/orchestration-service/${ORCHESTRATION_COMMIT_SHA}/src/rest/parameters/content-type.yaml > ./internal/orchestration/${ORCHESTRATION_API_VERSION}/parameters/content-type.yaml
#set +e
#yq -i e  '{"components": {"parameters": .}}' ./internal/orchestration/${ORCHESTRATION_API_VERSION}/parameters/content-type.yaml
#
# Download the scans model spec for the orchestration API
set -e
curl -s https://${GITHUB_PAT}@raw.githubusercontent.com/snyk/orchestration-service/${ORCHESTRATION_COMMIT_SHA}/src/rest/models/scans.yaml > ./internal/orchestration/${ORCHESTRATION_API_VERSION}/scans/scans.yaml
set +e
yq -i e  '{"components": .}' ./internal/orchestration/${ORCHESTRATION_API_VERSION}/scans/scans.yaml
sed -i '' "s@https://raw.githubusercontent.com/snyk/sweater-comb/common-model-v1/components/common.yaml#@../common/common.yaml#/components@g" ./internal/orchestration/${ORCHESTRATION_API_VERSION}/scans/scans.yaml
sed -i '' "s@'#/schemas/@'#/components/schemas/@g" ./internal/orchestration/${ORCHESTRATION_API_VERSION}/scans/scans.yaml
#sed -i '' "s@../../../../models/links.yaml#@../links/links.yaml#/components@g" ./internal/orchestration/${ORCHESTRATION_API_VERSION}/orchestrations/orchestrations.yaml

# Download the orchestration API spec
set -e
curl -s https://${GITHUB_PAT}@raw.githubusercontent.com/snyk/orchestration-service/${ORCHESTRATION_COMMIT_SHA}/src/rest/resources/scans/${ORCHESTRATION_API_VERSION}/spec.yaml > ./internal/orchestration/${ORCHESTRATION_API_VERSION}/spec.yaml
set +e
sed -i '' "s@../../../models/scans.yaml#/schemas@./scans/scans.yaml#/components/schemas@g" ./internal/orchestration/${ORCHESTRATION_API_VERSION}/spec.yaml
sed -i '' "s@#/components/x-snyk-common@./common/common.yaml#/components@g" ./internal/orchestration/${ORCHESTRATION_API_VERSION}/spec.yaml
sed -i '' "s@../../../parameters/orgs.yaml#@./parameters/orgs.yaml#/components/parameters@g" ./internal/orchestration/${ORCHESTRATION_API_VERSION}/spec.yaml
sed -i '' "s@../../../parameters/scans.yaml#@./parameters/scans.yaml#/components/parameters@g" ./internal/orchestration/${ORCHESTRATION_API_VERSION}/spec.yaml
#sed -i '' "s@../../../parameters/content-type.yaml#@./parameters/content-type.yaml#/components/parameters@g" ./internal/orchestration/${ORCHESTRATION_API_VERSION}/spec.yaml