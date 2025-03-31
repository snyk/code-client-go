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
	"github.com/snyk/code-client-go/v2/internal/util"
)

type BundleFile struct {
	Hash    string `json:"hash"`
	Content string `json:"content"`
}

func BundleFileFrom(content []byte) BundleFile {
	file := BundleFile{
		Hash:    util.Hash(content),
		Content: string(content),
	}
	return file
}
