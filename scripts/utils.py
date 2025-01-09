#!/usr/bin/env python3

import os
import json
import yaml
import base64
import sys
import pycurl
from io import BytesIO

def mkDir(directory):
	if not os.path.exists(directory):
		os.makedirs(directory)

def replaceInFile(search_text, replace_text, file):
	with open(file, 'r') as f:
		data = f.read()
		data = data.replace(search_text, replace_text)

	with open(file, 'w') as f:
		f.write(data)

def saveGitHubFile(gitHubRepo, gitHubFile, localFile, gitHubCommitSha):
	if "GITHUB_PAT" not in os.environ:
		print ("Could not run the script. The GITHUB_PAT environment variable must be set to a valid Personal Access Token.")
		sys.exit(1)

	gitHubPat = os.environ["GITHUB_PAT"]

	buffer = BytesIO()
	curl = pycurl.Curl()
	curl.setopt(curl.URL, f"https://api.github.com/repos/snyk/{gitHubRepo}/contents/{gitHubFile}?ref={gitHubCommitSha}")
	curl.setopt(curl.WRITEDATA, buffer)
	curl.setopt(curl.HTTPHEADER, [f"Authorization: token {gitHubPat}"])
	curl.perform()
	status_code = curl.getinfo(curl.RESPONSE_CODE)

	if status_code != 200:
		print(f"Could not retrieve file from GitHub {gitHubFile}.")
		print(buffer.getvalue().decode('UTF-8'))
		sys.exit(1)
	with open(localFile, "w") as f:
		response = json.loads(buffer.getvalue())
		f.write(base64.b64decode(response["content"]).decode('UTF-8'))
	curl.close()

# change structure of yaml to support code generator
def formatSpecWithComponents(file):
	with open(file, 'r') as f:
		obj = yaml.safe_load(f)

	with open(file, 'w') as f:
		nestedObj = {'components': obj}
		yaml.dump(nestedObj, f, sort_keys=False)

# change structure of yaml to support code generator
def formatSpecWithParameters(file):
	with open(file, 'r') as f:
		obj = yaml.safe_load(f)

	with open(file, 'w') as f:
		nestedObj = {'parameters': obj}
		yaml.dump(nestedObj, f, sort_keys=False)