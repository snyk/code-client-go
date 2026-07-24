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

// The transcoder is tested from inside the package because the upload client it is passed to
// enforces its size limits in megabytes, which makes the reported size unobservable from a test
// going through UploadRevision.
package uploadrevision

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newUTF8File_reportsTheConvertedSize(t *testing.T) {
	// Each byte that is not valid UTF-8 is converted to U+FFFD, which takes three bytes.
	f := openFile(t, append([]byte("package main"), 0xff))

	transcoded, err := newUTF8File(f)
	require.NoError(t, err)

	info, err := transcoded.Stat()
	require.NoError(t, err)
	assert.Equal(t, int64(15), info.Size())

	content, err := io.ReadAll(transcoded)
	require.NoError(t, err)
	assert.Equal(t, "package main�", string(content))
	assert.Len(t, content, int(info.Size()))
}

func Test_newUTF8File_reportsTheSameSizeAfterReading(t *testing.T) {
	f := openFile(t, append([]byte("package main"), 0xff))

	transcoded, err := newUTF8File(f)
	require.NoError(t, err)

	_, err = io.ReadAll(transcoded)
	require.NoError(t, err)

	info, err := transcoded.Stat()
	require.NoError(t, err)
	assert.Equal(t, int64(15), info.Size())
}

func Test_newUTF8File_keepsTheRemainingFileInfo(t *testing.T) {
	f := openFile(t, []byte("package main"))

	transcoded, err := newUTF8File(f)
	require.NoError(t, err)

	info, err := transcoded.Stat()
	require.NoError(t, err)
	assert.Equal(t, "main.go", info.Name())
	assert.True(t, info.Mode().IsRegular())
}

func openFile(t *testing.T, content []byte) *os.File {
	t.Helper()

	path := filepath.Join(t.TempDir(), "main.go")
	require.NoError(t, os.WriteFile(path, content, 0o600))

	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })

	return f
}
