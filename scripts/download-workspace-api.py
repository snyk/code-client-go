#!/usr/bin/env python3

from utils import mkDir
from utils import saveGitHubFile
from utils import formatSpecWithComponents
from utils import formatSpecWithParameters
from utils import replaceInFile

WORKSPACE_API_VERSION = "2024-05-14"
WORKSPACE_COMMIT_SHA = "2d8bd3b"

mkDir(f"./internal/workspace/{WORKSPACE_API_VERSION}")
mkDir(f"./internal/workspace/{WORKSPACE_API_VERSION}/common")
mkDir(f"./internal/workspace/{WORKSPACE_API_VERSION}/links")
mkDir(f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters")
mkDir(f"./internal/workspace/{WORKSPACE_API_VERSION}/workspaces")

# Download the Common spec
saveGitHubFile("sweater-comb", "components/common.yaml", f"./internal/workspace/{WORKSPACE_API_VERSION}/common/common.yaml", "main")
formatSpecWithComponents(f"./internal/workspace/{WORKSPACE_API_VERSION}/common/common.yaml")
replaceInFile("#/schemas/", "#/components/schemas/", f"./internal/workspace/{WORKSPACE_API_VERSION}/common/common.yaml")
replaceInFile("#/headers/", "#/components/headers/", f"./internal/workspace/{WORKSPACE_API_VERSION}/common/common.yaml")

# Download the Links model spec for the Workspace API
saveGitHubFile("workspace-service", f"src/rest/api/hidden/models/links.yaml", f"./internal/workspace/{WORKSPACE_API_VERSION}/links/links.yaml", WORKSPACE_COMMIT_SHA)
formatSpecWithComponents(f"./internal/workspace/{WORKSPACE_API_VERSION}/links/links.yaml")
replaceInFile("#/schemas", "#/components/schemas", f"./internal/workspace/{WORKSPACE_API_VERSION}/links/links.yaml")

# Download the Org parameter spec for the orchestration API
saveGitHubFile("workspace-service", f"src/rest/api/hidden/parameters/orgs.yaml", f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/orgs.yaml", WORKSPACE_COMMIT_SHA)
formatSpecWithParameters(f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/orgs.yaml")
formatSpecWithComponents(f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/orgs.yaml")

# Download the Request ID parameter spec for the Workspace API
saveGitHubFile("workspace-service", f"src/rest/api/hidden/parameters/request-id.yaml", f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/request-id.yaml", WORKSPACE_COMMIT_SHA)
formatSpecWithParameters(f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/request-id.yaml")
formatSpecWithComponents(f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/request-id.yaml")

# Download the User Agent parameter spec for the Workspace API
saveGitHubFile("workspace-service", f"src/rest/api/hidden/parameters/user-agent.yaml", f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/user-agent.yaml", WORKSPACE_COMMIT_SHA)
formatSpecWithParameters(f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/user-agent.yaml")
formatSpecWithComponents(f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/user-agent.yaml")

# Download the Content Type parameter spec for the Workspace API
saveGitHubFile("workspace-service", f"src/rest/api/hidden/parameters/content-type.yaml", f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/content-type.yaml", WORKSPACE_COMMIT_SHA)
formatSpecWithParameters(f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/content-type.yaml")
formatSpecWithComponents(f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/content-type.yaml")

# Download the Workspace model spec for the Workspace API
saveGitHubFile("workspace-service", f"src/rest/api/hidden/resources/workspaces/{WORKSPACE_API_VERSION}/models/workspaces.yaml", f"./internal/workspace/{WORKSPACE_API_VERSION}/workspaces/workspaces.yaml", WORKSPACE_COMMIT_SHA)
formatSpecWithComponents(f"./internal/workspace/{WORKSPACE_API_VERSION}/workspaces/workspaces.yaml")
replaceInFile("https://raw.githubusercontent.com/snyk/sweater-comb/common-model-v1/components/common.yaml#", "../common/common.yaml#/components", f"./internal/workspace/{WORKSPACE_API_VERSION}/workspaces/workspaces.yaml")
replaceInFile("../../../../models/links.yaml#", "../links/links.yaml#/components", f"./internal/workspace/{WORKSPACE_API_VERSION}/workspaces/workspaces.yaml")

# Download the orchestration API spec
saveGitHubFile("workspace-service", f"src/rest/api/hidden/resources/workspaces/{WORKSPACE_API_VERSION}/spec.yaml", f"./internal/workspace/{WORKSPACE_API_VERSION}/spec.yaml", WORKSPACE_COMMIT_SHA)
replaceInFile("../../../models/scans.yaml#/schemas", "./scans/scans.yaml#/components/schemas", f"./internal/workspace/{WORKSPACE_API_VERSION}/spec.yaml")
replaceInFile("#/components/x-snyk-common", "./common/common.yaml#/components", f"./internal/workspace/{WORKSPACE_API_VERSION}/spec.yaml")
replaceInFile("../../../parameters/orgs.yaml#", "./parameters/orgs.yaml#/components/parameters", f"./internal/workspace/{WORKSPACE_API_VERSION}/spec.yaml")
replaceInFile("../../../parameters/user-agent.yaml#", "./parameters/user-agent.yaml#/components/parameters", f"./internal/workspace/{WORKSPACE_API_VERSION}/spec.yaml")
replaceInFile("../../../parameters/content-type.yaml#", "./parameters/content-type.yaml#/components/parameters", f"./internal/workspace/{WORKSPACE_API_VERSION}/spec.yaml")
replaceInFile("../../../parameters/request-id.yaml#", "./parameters/request-id.yaml#/components/parameters", f"./internal/workspace/{WORKSPACE_API_VERSION}/spec.yaml")
replaceInFile("../../../parameters/scans.yaml#", "./parameters/scans.yaml#/components/parameters", f"./internal/workspace/{WORKSPACE_API_VERSION}/spec.yaml")
replaceInFile("./models/workspaces.yaml#/schemas", "./workspaces/workspaces.yaml#/components/schemas", f"./internal/workspace/{WORKSPACE_API_VERSION}/spec.yaml")
