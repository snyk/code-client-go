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
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetRepositoryUrl_no_repo(t *testing.T) {

	actualUrl, err := GetRepositoryUrl("")
	assert.NoError(t, err)
	assert.NotEmpty(t, actualUrl)
	fmt.Println(actualUrl)
}

func Test_CheckCredentials(t *testing.T) {
	t.Run("has credentials", func(t *testing.T) {
		urlWithCreds := "https://snykUser:snykSuperSecret@github.com/snyk/cli.git"

		hasCreds := hasCredentials(urlWithCreds)

		assert.True(t, hasCreds)
	})

	t.Run("no credentials", func(t *testing.T) {
		urlWithCreds := "https://github.com/snyk/cli.git"

		hasCreds := hasCredentials(urlWithCreds)

		assert.False(t, hasCreds)
	})
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
