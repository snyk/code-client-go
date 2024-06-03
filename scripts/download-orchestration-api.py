#!/usr/bin/env python3

from utils import mkDir
from utils import saveGitHubFile
from utils import formatSpecWithComponents
from utils import formatSpecWithParameters
from utils import replaceInFile

ORCHESTRATION_API_VERSION = "2024-02-16"
ORCHESTRATION_COMMIT_SHA = "a20671b"

mkDir(f"./internal/orchestration/{ORCHESTRATION_API_VERSION}")
mkDir(f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/common")
mkDir(f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/parameters")
mkDir(f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/scans")
mkDir(f"./internal/orchestration/{ORCHESTRATION_API_VERSION}")

# Download the Common spec
saveGitHubFile("sweater-comb", "components/common.yaml", f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/common/common.yaml", "main")
formatSpecWithComponents(f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/common/common.yaml")
replaceInFile("#/schemas/", "#/components/schemas/", f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/common/common.yaml")
replaceInFile("#/headers/", "#/components/headers/", f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/common/common.yaml")

# Download the Org parameter spec for the orchestration API
saveGitHubFile("orchestration-service", f"src/rest/parameters/orgs.yaml", f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/parameters/orgs.yaml", ORCHESTRATION_COMMIT_SHA)
formatSpecWithParameters(f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/parameters/orgs.yaml")
formatSpecWithComponents(f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/parameters/orgs.yaml")

# Download the Scan parameter spec for the orchestration API
saveGitHubFile("orchestration-service", f"src/rest/parameters/scans.yaml", f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/parameters/scans.yaml", ORCHESTRATION_COMMIT_SHA)
formatSpecWithParameters(f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/parameters/scans.yaml")
formatSpecWithComponents(f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/parameters/scans.yaml")

# Download the scans model spec for the orchestration API
saveGitHubFile("orchestration-service", f"src/rest/models/scans.yaml", f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/scans/scans.yaml", ORCHESTRATION_COMMIT_SHA)
formatSpecWithComponents(f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/scans/scans.yaml")
replaceInFile("https://raw.githubusercontent.com/snyk/sweater-comb/common-model-v1/components/common.yaml#", "../common/common.yaml#/components", f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/scans/scans.yaml")
replaceInFile("'#/schemas/", "'#/components/schemas/", f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/scans/scans.yaml")

# Download the orchestration API spec
saveGitHubFile("orchestration-service", f"src/rest/resources/scans/{ORCHESTRATION_API_VERSION}/spec.yaml", f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/spec.yaml", ORCHESTRATION_COMMIT_SHA)
replaceInFile("../../../models/scans.yaml#/schemas", "./scans/scans.yaml#/components/schemas", f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/spec.yaml")
replaceInFile("#/components/x-snyk-common", "./common/common.yaml#/components", f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/spec.yaml")
replaceInFile("../../../parameters/orgs.yaml#", "./parameters/orgs.yaml#/components/parameters", f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/spec.yaml")
replaceInFile("../../../parameters/scans.yaml#", "./parameters/scans.yaml#/components/parameters", f"./internal/orchestration/{ORCHESTRATION_API_VERSION}/spec.yaml")
