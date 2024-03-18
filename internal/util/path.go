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
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

func ToRelativeUnixPath(baseDir string, absoluteFilePath string) (string, error) {
	relativePath, err := filepath.Rel(baseDir, absoluteFilePath)
	if err != nil {
		relativePath = absoluteFilePath
		if baseDir != "" {
			errMsg := fmt.Sprint("could not get relative path for file: ", absoluteFilePath, " and root path: ", baseDir)
			return "", errors.Wrap(err, errMsg)
		}
	}

	relativePath = filepath.ToSlash(relativePath) // treat all paths as unix paths
	return relativePath, nil
}

func ToAbsolutePath(baseDir string, relativePath string) string {
	return filepath.Join(baseDir, relativePath)
}

func EncodePath(relativePath string) string {
	segments := strings.Split(filepath.ToSlash(relativePath), "/")
	encodedPath := ""
	for _, segment := range segments {
		encodedSegment := url.PathEscape(segment)
		encodedPath = path.Join(encodedPath, encodedSegment)
	}

	return encodedPath
}

func DecodePath(encodedRelativePath string) (string, error) {
	return url.PathUnescape(encodedRelativePath)
}
