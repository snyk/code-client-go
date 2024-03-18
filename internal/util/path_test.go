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
	"github.com/snyk/code-client-go/internal/util"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHttp_ToRelativeUnixPath(t *testing.T) {
	expected, err := util.ToRelativeUnixPath("baseDir", "baseDir/foo/bar")
	assert.NoError(t, err)
	assert.Equal(t, "foo/bar", expected)
}

func TestHttp_ToAbsolutePath(t *testing.T) {
	assert.Equal(t, "baseDir/foo/bar", util.ToAbsolutePath("baseDir", "foo/bar"))
}

func TestHttp_EncodePath(t *testing.T) {
	assert.Equal(t, "path/path%20with%20space", util.EncodePath("path/path with space"))
}

func TestHttp_DecodePath(t *testing.T) {
	actual, err := util.DecodePath("path/path%20with%20space")
	assert.NoError(t, err)
	assert.Equal(t, "path/path with space", actual)
}
