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
	"net/url"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/assert"
)

func Test_GetRepositoryUrl_repo(t *testing.T) {
	// check out a repo and prepare its config to contain credentials in the URL
	expectedRepoUrl := "https://github.com/snyk-fixtures/shallow-goof-locked.git"

	repoDir := t.TempDir()
	repo, err := git.PlainClone(repoDir, false, &git.CloneOptions{URL: expectedRepoUrl})
	assert.NoError(t, err)
	assert.NotNil(t, repo)

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
	actualUrl, err := GetRepositoryUrl(repoDir)
	assert.NoError(t, err)
	assert.Equal(t, expectedRepoUrl, actualUrl)
}

func Test_GetRepositoryUrl_no_repo(t *testing.T) {
	repoDir := t.TempDir()
	actualUrl, err := GetRepositoryUrl(repoDir)
	assert.Error(t, err)
	assert.Empty(t, actualUrl)
}

func Test_SanatiseUrl_url_with_creds(t *testing.T) {
	expectedUrl := "https://github.com/snyk/cli.git"

	t.Run("has credentials", func(t *testing.T) {
		inputUrl := "https://snykUser:snykSuperSecret@github.com/snyk/cli.git"
		actualUrl, err := sanitiseCredentials(inputUrl)
		assert.NoError(t, err)
		assert.Equal(t, expectedUrl, actualUrl)
	})

	t.Run("no credentials", func(t *testing.T) {
		inputUrl := "https://github.com/snyk/cli.git"
		actualUrl, err := sanitiseCredentials(inputUrl)
		assert.NoError(t, err)
		assert.Equal(t, expectedUrl, actualUrl)
	})

	t.Run("no http url", func(t *testing.T) {
		inputUrl := "git@github.com:snyk/code-client-go.git"
		actualUrl, err := sanitiseCredentials(inputUrl)
		assert.NoError(t, err)
		assert.Equal(t, inputUrl, actualUrl)
	})
}
