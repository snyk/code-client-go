import requests
import os
import json
import yaml

def mkDir(directory):
	if not os.path.exists(directory):
		os.makedirs(directory)

def replaceInFile(search_text, replace_text, file):
	with open(file, 'r') as f:
		data = f.read()
		data = data.replace(search_text, replace_text)

	with open(file, 'w') as f:
		f.write(data)

def saveGitHubFile(gitHubFile, localFile):
	if "GITHUB_PAT" not in os.environ:
		print >> sys.stderr, "Could not run the script. The GITHUB_PAT environment variable must be set to a valid Personal Access Token."
		sys.exit(1)

	gitHubPat = os.environ["GITHUB_PAT"]
	response = requests.get(f"https://{gitHubPat}@raw.githubusercontent.com/snyk/{gitHubFile}", headers={'Accept': 'application/json'})

	with open(localFile, "w") as f:
		f.write(response.text)

def formatSpecWithComponents(file):
	with open(file, 'r') as f:
		obj = yaml.safe_load(f)

	with open(file, 'w') as f:
		nestedObj = {'components': obj}
		yaml.dump(nestedObj, f, sort_keys=False)

def formatSpecWithParameters(file):
	with open(file, 'r') as f:
		obj = yaml.safe_load(f)

	with open(file, 'w') as f:
		nestedObj = {'parameters': obj}
		yaml.dump(nestedObj, f, sort_keys=False)
