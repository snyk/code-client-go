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

// GetRepositoryUrl resolves the remote repository URL for the checkout at path
// from the "origin" remote.
//
// The repository URL is what associates findings with an SCM asset/project, so a
// missing URL silently disables consistent-ignores. Only the "origin" remote is
// used: findings are never attributed to a different remote that happens to be
// configured. The returned URL is stripped of any embedded credentials.
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

	urls := remote.Config().URLs
	if len(urls) == 0 || urls[0] == "" {
		return "", fmt.Errorf("%s: no repository urls available", failureContext)
	}

	// based on the docs, the first URL is the one used to fetch
	return SanitiseCredentials(urls[0])
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

func GetBranchName(path string) (string, error) {
	failureContext := "failed to get branch name"
	repo, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return "", fmt.Errorf("%s: open local repository: %w", failureContext, err)
	}

	ref, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf("%s: get repo head: %w", failureContext, err)
	}

	if !ref.Name().IsBranch() {
		return "", fmt.Errorf("%s: current ref is not a branch: %w", failureContext, err)
	}
	return ref.Name().Short(), nil
}

// SanitiseCredentials returns the repository URL with any embedded credentials
// removed. It never returns a URL that still contains a secret:
//
//   - Standard URLs (those with a "scheme://" - https, ssh, git, ...) have their
//     entire userinfo component stripped.
//   - scp-style SSH remotes ("[user@]host:path", which have no scheme) are
//     returned unchanged: the user component (e.g. "git") is not a secret, and a
//     password cannot appear in this syntax. An "@" at or after the host:path
//     ":" belongs to the path (e.g. an email address in the path) and is
//     preserved, so "host:dir/a@b.com/repo.git" is not mangled.
//   - Input that cannot be confidently sanitized (a "scheme://" URL that fails to
//     parse, where credentials could be present in an unknown position) fails
//     closed with an error rather than returning the raw, credential-bearing
//     string.
func SanitiseCredentials(rawURL string) (string, error) {
	if strings.Contains(rawURL, "://") {
		parsedURL, err := url.Parse(rawURL)
		if err != nil {
			// We cannot reason about where credentials sit in a malformed URL,
			// so refuse to return it rather than risk leaking a secret.
			return "", fmt.Errorf("unable to sanitize repository url credentials: %w", err)
		}
		parsedURL.User = nil
		return parsedURL.String(), nil
	}

	// No scheme: treat as scp-style syntax "[user@]host:path".
	at := strings.Index(rawURL, "@")
	if at < 0 {
		// No userinfo, so no credentials to strip.
		return rawURL, nil
	}
	// In scp syntax the first ":" separates host from path. A ":" before the
	// first "@" means the "@" is in the path, not userinfo - nothing to strip.
	if colon := strings.Index(rawURL, ":"); colon >= 0 && colon < at {
		return rawURL, nil
	}
	userinfo := rawURL[:at]
	rest := rawURL[at+1:]
	if userinfo == "" {
		return rest, nil
	}
	return userinfo + "@" + rest, nil
}
