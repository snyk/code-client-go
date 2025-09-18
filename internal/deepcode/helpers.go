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
package deepcode

import (
	"github.com/snyk/code-client-go/internal/util"
)

type BundleFile struct {
	Hash        string `json:"hash"`
	Content     string `json:"content"`
	ContentSize int    `json:"-"`
}

func BundleFileFrom(content []byte, includeContent bool) (BundleFile, error) {
	hash, err := util.Hash(content)

	// We can either create the bundleFile empty and enrich it with content later, or include the content now.
	// Creating empty avoids keeping the file contents in memory, so improves performance if we don't need access to the
	// contents right away.
	bundleFileContent := ""
	if includeContent {
		utf8Content, convertErr := util.ConvertToUTF8(content)
		if convertErr == nil {
			bundleFileContent = string(utf8Content)
		} else {
			bundleFileContent = string(content)
			err = convertErr
		}
	}

	file := BundleFile{
		Hash:        hash,
		Content:     bundleFileContent,
		ContentSize: len(content),
	}
	return file, err
}
