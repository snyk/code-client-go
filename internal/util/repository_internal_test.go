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
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func gitAvailable() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

func Test_getRepositoryUrlViaGitBinary_resolves_origin(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git binary not available")
	}
	repoDir := t.TempDir()
	expectedRepoUrl := "https://github.com/snyk-fixtures/shallow-goof-locked.git"

	require.NoError(t, exec.Command("git", "-C", repoDir, "init").Run())
	require.NoError(t, exec.Command("git", "-C", repoDir, "remote", "add", "origin", expectedRepoUrl).Run())

	actualUrl, err := getRepositoryUrlViaGitBinary(repoDir)
	assert.NoError(t, err)
	assert.Equal(t, expectedRepoUrl, actualUrl)
}

func Test_getRepositoryUrlViaGitBinary_no_origin(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git binary not available")
	}
	repoDir := t.TempDir()
	require.NoError(t, exec.Command("git", "-C", repoDir, "init").Run())

	actualUrl, err := getRepositoryUrlViaGitBinary(repoDir)
	assert.Error(t, err)
	assert.Empty(t, actualUrl)
}

func Test_validatedRepoDir(t *testing.T) {
	dir := t.TempDir()

	resolved, err := validatedRepoDir(dir)
	assert.NoError(t, err)
	assert.Equal(t, dir, resolved)

	// a path that does not exist is rejected
	_, err = validatedRepoDir(filepath.Join(dir, "does-not-exist"))
	assert.Error(t, err)
}

// Test_GetRepositoryUrl_origin_sanitized drives the public entry point end-to-end
// via the go-git path and asserts credentials are stripped.
func Test_GetRepositoryUrl_origin_sanitized(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git binary not available")
	}
	repoDir := t.TempDir()
	require.NoError(t, exec.Command("git", "-C", repoDir, "init").Run())
	require.NoError(t, exec.Command("git", "-C", repoDir, "remote", "add", "origin",
		"https://user:token@github.com/org/repo.git").Run())

	got, err := GetRepositoryUrl(repoDir)
	require.NoError(t, err)
	assert.Equal(t, "https://github.com/org/repo.git", got)
	assert.NotContains(t, got, "token")
}

// Test_GetRepositoryUrl_no_repo_errors covers the no-repository case end-to-end:
// neither go-git nor the git binary fallback can produce a URL.
func Test_GetRepositoryUrl_no_repo_errors(t *testing.T) {
	repoDir := t.TempDir()

	got, err := GetRepositoryUrl(repoDir)
	assert.Error(t, err)
	assert.Empty(t, got)
}

// Test_GetRepositoryUrl_uses_git_binary_fallback exercises the binary fallback
// path end-to-end: origin is defined only in a file pulled in via an [include]
// directive. The git binary follows includes; go-git does not, so resolution must
// fall through go-git to the git binary and still return the sanitized URL.
func Test_GetRepositoryUrl_uses_git_binary_fallback(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git binary not available")
	}
	repoDir := t.TempDir()
	require.NoError(t, exec.Command("git", "-C", repoDir, "init").Run())

	includedPath := filepath.Join(repoDir, "extra.config")
	require.NoError(t, os.WriteFile(includedPath,
		[]byte("[remote \"origin\"]\n\turl = https://user:token@github.com/org/repo.git\n"), 0o600))
	// absolute include path so resolution does not depend on the config file's dir
	require.NoError(t, exec.Command("git", "-C", repoDir, "config", "--local",
		"include.path", includedPath).Run())

	// Precondition: go-git cannot see origin (it does not process includes).
	_, goGitErr := getOriginUrlViaGoGit(repoDir)
	require.Error(t, goGitErr)

	got, err := GetRepositoryUrl(repoDir)
	require.NoError(t, err)
	assert.Equal(t, "https://github.com/org/repo.git", got)
	assert.NotContains(t, got, "token")
}
