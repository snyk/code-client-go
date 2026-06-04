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
	"bytes"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
)

// GetRepositoryUrl resolves the "origin" remote repository URL for the checkout
// at path.
//
// The repository URL is what associates findings with an SCM asset/project, so a
// missing URL silently disables consistent-ignores. Only the "origin" remote is
// used: findings are never attributed to a different remote that happens to be
// configured. Resolution first uses go-git and, if that produces no URL, falls
// back to the system git binary (which resolves config forms go-git can
// mis-parse). The returned URL is stripped of any embedded credentials.
func GetRepositoryUrl(path string) (string, error) {
	failureContext := "failed to get repository url"

	repoUrl, goGitErr := getOriginUrlViaGoGit(path)
	if goGitErr == nil && repoUrl != "" {
		return SanitiseCredentials(repoUrl)
	}

	if binUrl, binErr := getRepositoryUrlViaGitBinary(path); binErr == nil && binUrl != "" {
		return SanitiseCredentials(binUrl)
	}

	if goGitErr != nil {
		return "", fmt.Errorf("%s: %w", failureContext, goGitErr)
	}
	return "", fmt.Errorf("%s: no repository urls available", failureContext)
}

// getOriginUrlViaGoGit reads the "origin" remote's first URL using go-git.
func getOriginUrlViaGoGit(path string) (string, error) {
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

	urls := remote.Config().URLs
	if len(urls) == 0 || urls[0] == "" {
		return "", fmt.Errorf("no repository urls available")
	}

	// based on the docs, the first URL is the one used to fetch
	return urls[0], nil
}

// getRepositoryUrlViaGitBinary resolves the "origin" remote URL by invoking the
// system git binary. It reads the stored URL with git's own config parser, which
// covers config forms go-git can mis-parse (e.g. include directives) and returns
// the same canonical URL git uses. It does not apply url.<base>.insteadOf
// rewrites (which could change the URL away from the imported asset's URL) and it
// does not contact the network.
func getRepositoryUrlViaGitBinary(path string) (string, error) {
	dir, err := validatedRepoDir(path)
	if err != nil {
		return "", err
	}

	out, err := runGitInDir(dir, "config", "--get", "remote.origin.url")
	if err != nil {
		return "", err
	}
	if out == "" {
		return "", fmt.Errorf("no repository url available from git")
	}
	return out, nil
}

// runGitInDir runs the system git binary inside dir with a fixed set of constant
// arguments and returns trimmed stdout.
//
// "-c safe.directory=*" is prepended so the lookup also works in CI containers
// where the checkout is owned by a different UID than the running process (git
// otherwise refuses with "detected dubious ownership"). This is safe for a
// read-only "git config --get": no hooks, checkout, or other code paths that
// could execute repository-controlled code are triggered, so trusting the
// directory cannot lead to code execution. Using "*" rather than the directory
// also keeps every argument a constant literal.
func runGitInDir(dir string, args ...string) (string, error) {
	gitArgs := append([]string{"-c", "safe.directory=*"}, args...)
	// #nosec G204 -- "git" is a constant executable, all arguments are constant
	// literals, and dir is supplied only as the working directory (cmd.Dir),
	// never as part of the argument vector; no shell is involved.
	cmd := exec.Command("git", gitArgs...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(stdout.String()), nil
}

// validatedRepoDir cleans path and returns the directory to run git in (the
// parent directory when path points at a file).
//
// The os.Stat call is a best-effort existence/type check to avoid spawning git
// against a missing path; it is NOT a security boundary. Command-injection safety
// comes solely from the fact that this value is only ever passed as the git
// process working directory (cmd.Dir), never as a command argument.
func validatedRepoDir(path string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		abs = filepath.Dir(abs)
	}
	return abs, nil
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
