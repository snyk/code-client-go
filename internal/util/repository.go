/*
 * © 2024 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package util

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/go-git/go-git/v5"
)

func GetRepositoryUrl(path string) (string, error) {
	repo, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return "", fmt.Errorf("open local repository: %w", err)
	}

	remote, err := repo.Remote("origin")
	if err != nil {
		return "", fmt.Errorf("get remote: %w", err)
	}

	if len(remote.Config().URLs) == 0 {
		return "", fmt.Errorf("no repository urls available")
	}

	// based on the docs, the first URL is being used to fetch, so this is the one we use
	repoUrl := remote.Config().URLs[0]
	repoUrl, err = SanitiseCredentials(repoUrl)

	// we need to return an actual URL, not the SSH
	repoUrl = strings.Replace(repoUrl, "git@github.com:", "https://github.com/", 1)
	return repoUrl, err
}

func SanitiseCredentials(rawUrl string) (string, error) {
	parsedURL, err := url.Parse(rawUrl)
	if err != nil {
		return rawUrl, nil
	}

	parsedURL.User = nil
	strippedUrl := parsedURL.String()

	return strippedUrl, nil
}
