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

	"github.com/go-git/go-git/v5"
)

func GetRepositoryUrl(path string) (string, error) {
	failureContext := "failed to get repository url"
	repo, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return "", fmt.Errorf("%s: open local repository: %w", failureContext, err)
	}

	remote, err := repo.Remote("origin")
	if err != nil {
		return "", fmt.Errorf("%s: get remote: %w", failureContext, err)
	}

	if len(remote.Config().URLs) == 0 {
		return "", fmt.Errorf("%s: no repository urls available", failureContext)
	}

	// based on the docs, the first URL is being used to fetch, so this is the one we use
	repoUrl := remote.Config().URLs[0]
	repoUrl, err = SanitiseCredentials(repoUrl)

	return repoUrl, err
}

func GetCommitId(path string) (string, error) {
	failureContext := "failed to get commit id"
	repo, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return "", fmt.Errorf("%s: open local repository: %w", failureContext, err)
	}

	commitId, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf("%s: get commit id: %w", failureContext, err)
	}

	return commitId.Hash().String(), nil
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
