from utils import mkDir
from utils import saveGitHubFile
from utils import formatSpecWithComponents
from utils import formatSpecWithParameters
from utils import replaceInFile

WORKSPACE_API_VERSION = "2024-03-12"
WORKSPACE_COMMIT_SHA = "cfd737cd917ab2c63840bd112d9eb2c9a9c101f6"

mkDir(f"./internal/workspace/{WORKSPACE_API_VERSION}")

# Download the Common spec
saveGitHubFile("sweater-comb/common-model-v1/components/common.yaml", f"./internal/workspace/{WORKSPACE_API_VERSION}/common/common.yaml")
formatSpecWithComponents(f"./internal/workspace/{WORKSPACE_API_VERSION}/common/common.yaml")
replaceInFile("#/schemas/", "#/components/schemas/", f"./internal/workspace/{WORKSPACE_API_VERSION}/common/common.yaml")
replaceInFile("#/headers/", "#/components/headers/", f"./internal/workspace/{WORKSPACE_API_VERSION}/common/common.yaml")

# Download the Links model spec for the Workspace API
saveGitHubFile(f"workspace-service/{WORKSPACE_COMMIT_SHA}/src/rest/api/hidden/models/links.yaml", f"./internal/workspace/{WORKSPACE_API_VERSION}/links/links.yaml")
formatSpecWithComponents(f"./internal/workspace/{WORKSPACE_API_VERSION}/links/links.yaml")
replaceInFile("#/schemas", "#/components/schemas", f"./internal/workspace/{WORKSPACE_API_VERSION}/links/links.yaml")

# Download the Org parameter spec for the orchestration API
saveGitHubFile(f"orchestration-service/{WORKSPACE_COMMIT_SHA}/src/rest/parameters/orgs.yaml", f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/orgs.yaml")
formatSpecWithParameters(f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/orgs.yaml")
formatSpecWithComponents(f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/orgs.yaml")

# Download the Request ID parameter spec for the Workspace API
saveGitHubFile(f"workspace-service/{WORKSPACE_COMMIT_SHA}/src/rest/api/hidden/parameters/request-id.yaml", f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/request-id.yaml")
formatSpecWithParameters(f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/request-id.yaml")
formatSpecWithComponents(f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/request-id.yaml")

# Download the User Agent parameter spec for the Workspace API
saveGitHubFile(f"workspace-service/{WORKSPACE_COMMIT_SHA}/src/rest/api/hidden/parameters/user-agent.yaml", f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/user-agent.yaml")
formatSpecWithParameters(f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/user-agent.yaml")
formatSpecWithComponents(f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/user-agent.yaml")

# Download the Content Type parameter spec for the Workspace API
saveGitHubFile(f"workspace-service/{WORKSPACE_COMMIT_SHA}/src/rest/api/hidden/parameters/content-type.yaml", f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/content-type.yaml")
formatSpecWithParameters(f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/content-type.yaml")
formatSpecWithComponents(f"./internal/workspace/{WORKSPACE_API_VERSION}/parameters/content-type.yaml")

# Download the Workspace model spec for the Workspace API
saveGitHubFile(f"workspace-service/{WORKSPACE_COMMIT_SHA}/src/rest/api/hidden/resources/workspaces/{WORKSPACE_API_VERSION}/models/workspaces.yaml", f"./internal/workspace/{WORKSPACE_API_VERSION}/workspaces/workspaces.yaml")
formatSpecWithComponents(f"./internal/workspace/{WORKSPACE_API_VERSION}/workspaces/workspaces.yaml")
replaceInFile("https://raw.githubusercontent.com/snyk/sweater-comb/common-model-v1/components/common.yaml#", "../common/common.yaml#/components@g", f"./internal/workspace/{WORKSPACE_API_VERSION}/workspaces/workspaces.yaml")
replaceInFile("../../../../models/links.yaml#", "../links/links.yaml#/components", f"./internal/workspace/{WORKSPACE_API_VERSION}/workspaces/workspaces.yaml")

# Download the orchestration API spec
saveGitHubFile(f"workspace-service/{WORKSPACE_COMMIT_SHA}/src/rest/api/hidden/resources/workspaces/{WORKSPACE_API_VERSION}/spec.yaml", f"./internal/workspace/{WORKSPACE_API_VERSION}/spec.yaml")
replaceInFile("../../../models/scans.yaml#/schemas", "./scans/scans.yaml#/components/schemas", f"./internal/workspace/{WORKSPACE_API_VERSION}/spec.yaml")
replaceInFile("#/components/x-snyk-common", "./common/common.yaml#/components", f"./internal/workspace/{WORKSPACE_API_VERSION}/spec.yaml")
replaceInFile("../../../parameters/orgs.yaml#", "./parameters/orgs.yaml#/components/parameters", f"./internal/workspace/{WORKSPACE_API_VERSION}/spec.yaml")
replaceInFile("../../../parameters/scans.yaml#", "./parameters/scans.yaml#/components/parameters", f"./internal/workspace/{WORKSPACE_API_VERSION}/spec.yaml")
