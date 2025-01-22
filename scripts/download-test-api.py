#!/usr/bin/env python3

# In this script
# * we download OpenAPI Specifications from different sources and combine them as one local Specification
# * we also adapt references and structure make local references work and use oapi-codegen to generate go code

from utils import mkDir
from utils import saveGitHubFile
from utils import formatSpecWithComponents
from utils import formatSpecWithParameters
from utils import replaceInFile

API_VERSION = "2024-12-21"
COMMIT_SHA = "ee94bf66e15c9229b4dfec623082267740165d0e"
SERVICE = "test-service"
FOLDER = "test"
BASELOCALDIR = f"./internal/api/{FOLDER}/{API_VERSION}"

mkDir(BASELOCALDIR)
mkDir(f"{BASELOCALDIR}/common")
mkDir(f"{BASELOCALDIR}/parameters")
mkDir(f"{BASELOCALDIR}/models")

# Download main spec file
saveGitHubFile(SERVICE, f"internal/api/public/resources/tests/{API_VERSION}/spec.yaml", f"{BASELOCALDIR}/spec.yaml", COMMIT_SHA)
replaceInFile("#/components/x-snyk-common", "./common/common.yaml#/components", f"{BASELOCALDIR}/spec.yaml")
replaceInFile("../../../../parameters/orgs.yaml#", "./parameters/orgs.yaml#/components/parameters", f"{BASELOCALDIR}/spec.yaml")
replaceInFile("../../../../parameters/tests.yaml#", "./parameters/tests.yaml#/components/parameters", f"{BASELOCALDIR}/spec.yaml")
replaceInFile("../../../../models/tests.yaml#", "./models/tests.yaml#/components", f"{BASELOCALDIR}/spec.yaml")

# Download common spec
saveGitHubFile("sweater-comb", "components/common.yaml", f"{BASELOCALDIR}/common/common.yaml", "main")
formatSpecWithComponents(f"{BASELOCALDIR}/common/common.yaml")
replaceInFile("#/schemas/", "#/components/schemas/", f"{BASELOCALDIR}/common/common.yaml")
replaceInFile("#/headers/", "#/components/headers/", f"{BASELOCALDIR}/common/common.yaml")

# Download orgs spec
saveGitHubFile(SERVICE, f"internal/api/parameters/orgs.yaml", f"{BASELOCALDIR}/parameters/orgs.yaml", COMMIT_SHA)
formatSpecWithParameters(f"{BASELOCALDIR}/parameters/orgs.yaml")
formatSpecWithComponents(f"{BASELOCALDIR}/parameters/orgs.yaml")

# Download tests spec
saveGitHubFile(SERVICE, f"internal/api/parameters/tests.yaml", f"{BASELOCALDIR}/parameters/tests.yaml", COMMIT_SHA)
formatSpecWithParameters(f"{BASELOCALDIR}/parameters/tests.yaml")
formatSpecWithComponents(f"{BASELOCALDIR}/parameters/tests.yaml")

# Download models spec
saveGitHubFile(SERVICE, f"internal/api/models/tests.yaml", f"{BASELOCALDIR}/models/tests.yaml", COMMIT_SHA)
replaceInFile("https://raw.githubusercontent.com/snyk/sweater-comb/common-model-v1/components/common.yaml#", "../common/common.yaml#/components", f"{BASELOCALDIR}/models/tests.yaml")
formatSpecWithComponents(f"{BASELOCALDIR}/models/tests.yaml")
replaceInFile("#/schemas/", "#/components/schemas/", f"{BASELOCALDIR}/models/tests.yaml")



