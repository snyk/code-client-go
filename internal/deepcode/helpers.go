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
	// Convert to UTF-8 once and reuse the result for both the hash and the
	// content. The previous implementation converted twice (once inside
	// util.Hash and once here), doubling the conversion cost for every file.
	utf8Content, err := util.ConvertToUTF8(content)
	if err != nil {
		utf8Content = content
	}

	hash := util.HashContent(utf8Content)

	// We can either create the bundleFile empty and enrich it with content later, or include the content now.
	// Creating empty avoids keeping the file contents in memory, so improves performance if we don't need access to the
	// contents right away.
	bundleFileContent := ""
	if includeContent {
		bundleFileContent = string(utf8Content)
	}

	file := BundleFile{
		Hash:        hash,
		Content:     bundleFileContent,
		ContentSize: len(content),
	}
	return file, err
}
