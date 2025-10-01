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
package util_test

import (
	"net/url"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/code-client-go/internal/util"
	"github.com/snyk/code-client-go/internal/util/testutil"
)

func Test_GetRepositoryUrl_repo_with_credentials(t *testing.T) {
	// check out a repo and prepare its config to contain credentials in the URL
	expectedRepoUrl := "https://github.com/snyk-fixtures/shallow-goof-locked.git"

	repoDir, err := testutil.SetupCustomTestRepo(t, expectedRepoUrl, "master", "", "shallow-goof-locked")
	require.NoError(t, err)

	repo, err := git.PlainOpenWithOptions(repoDir, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	require.NoError(t, err)

	config, err := repo.Config()
	assert.NoError(t, err)

	for i, remoteUrl := range config.Remotes["origin"].URLs {
		parsedRemoteUrl, errLocal := url.Parse(remoteUrl)
		assert.NoError(t, errLocal)
		parsedRemoteUrl.User = url.UserPassword("albert", "einstein")
		config.Remotes["origin"].URLs[i] = parsedRemoteUrl.String()
	}

	err = repo.SetConfig(config)
	assert.NoError(t, err)

	// run method under test
	actualUrl, err := util.GetRepositoryUrl(repoDir)
	assert.NoError(t, err)
	assert.Equal(t, expectedRepoUrl, actualUrl)
}

func Test_GetRepositoryUrl_repo_without_credentials(t *testing.T) {
	// check out a repo and prepare its config to contain credentials in the URL
	expectedRepoUrl := "https://github.com/snyk-fixtures/shallow-goof-locked.git"
	repoDir, err := testutil.SetupCustomTestRepo(t, expectedRepoUrl, "master", "", "shallow-goof-locked")
	require.NoError(t, err)

	// run method under test
	actualUrl, err := util.GetRepositoryUrl(repoDir)
	assert.NoError(t, err)
	assert.Equal(t, expectedRepoUrl, actualUrl)
}

func Test_GetRepositoryUrl_no_repo(t *testing.T) {
	repoDir := t.TempDir()
	actualUrl, err := util.GetRepositoryUrl(repoDir)
	assert.Error(t, err)
	assert.Empty(t, actualUrl)
}

func Test_GetRepositoryUrl_repo_subfolder(t *testing.T) {
	expectedRepoUrl := "https://github.com/snyk-fixtures/mono-repo.git"
	repoDir, err := testutil.SetupCustomTestRepo(t, expectedRepoUrl, "master", "", "mono-repo")
	require.NoError(t, err)

	// run method under test
	actualUrl, err := util.GetRepositoryUrl(filepath.Join(repoDir, "multi-module"))
	assert.NoError(t, err)
	assert.Equal(t, expectedRepoUrl, actualUrl)
}

func Test_GetRepositoryUrl_repo_submodule(t *testing.T) {
	parentRepoDir, err := testutil.SetupCustomTestRepo(t, "https://github.com/snyk-fixtures/shallow-goof-locked.git", "master", "", "shallow-goof-locked")
	require.NoError(t, err)
	nestedRepoDir, err := testutil.SetupCustomTestRepo(t, "https://github.com/snyk-fixtures/mono-repo.git", "master", parentRepoDir, "mono-repo")
	require.NoError(t, err)

	// run method under test
	actualUrl, err := util.GetRepositoryUrl(parentRepoDir)
	assert.NoError(t, err)
	assert.Equal(t, "https://github.com/snyk-fixtures/shallow-goof-locked.git", actualUrl)

	actualUrl, err = util.GetRepositoryUrl(nestedRepoDir)
	assert.NoError(t, err)
	assert.Equal(t, "https://github.com/snyk-fixtures/mono-repo.git", actualUrl)
}

func Test_GetCommitId_valid_repo(t *testing.T) {
	expectedRepoUrl := "https://github.com/snyk-fixtures/shallow-goof-locked.git"
	repoDir, err := testutil.SetupCustomTestRepo(t, expectedRepoUrl, "master", "", "shallow-goof-locked")
	require.NoError(t, err)

	commitId, err := util.GetCommitId(repoDir)
	assert.NoError(t, err)
	assert.NotEmpty(t, commitId)
	assert.Regexp(t, "^[a-f0-9]{40}$", commitId)
}

func Test_GetCommitId_repo_subfolder(t *testing.T) {
	expectedRepoUrl := "https://github.com/snyk-fixtures/mono-repo.git"
	repoDir, err := testutil.SetupCustomTestRepo(t, expectedRepoUrl, "master", "", "mono-repo")
	require.NoError(t, err)

	commitId, err := util.GetCommitId(filepath.Join(repoDir, "multi-module"))
	assert.NoError(t, err)
	assert.NotEmpty(t, commitId)
	assert.Len(t, commitId, 40)
	assert.Regexp(t, "^[a-f0-9]{40}$", commitId)
}

func Test_GetCommitId_no_repo(t *testing.T) {
	repoDir := t.TempDir()

	commitId, err := util.GetCommitId(repoDir)
	assert.Error(t, err)
	assert.Empty(t, commitId)
	assert.Contains(t, err.Error(), "open local repository")
}

func Test_GetCommitId_nonexistent_path(t *testing.T) {
	nonexistentPath := "/path/that/does/not/exist"

	commitId, err := util.GetCommitId(nonexistentPath)
	assert.Error(t, err)
	assert.Empty(t, commitId)
	assert.Contains(t, err.Error(), "open local repository")
}
