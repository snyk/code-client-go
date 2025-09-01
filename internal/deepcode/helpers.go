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
	"bytes"
	"net/http"

	"github.com/snyk/code-client-go/internal/util"
	"github.com/snyk/code-client-go/internal/util/encoding"
)

type BundleFile struct {
	Hash        string `json:"hash"`
	Content     string `json:"content"`
	ContentSize int    `json:"-"`
}

func BundleFileFrom(content []byte) (BundleFile, error) {
	hash, err := util.Hash(content)
	file := BundleFile{
		Hash:        hash,
		Content:     "", // We create the bundleFile empty, and enrich  with content later.
		ContentSize: len(content),
	}
	return file, err
}

func AddHeaders(method string, req *http.Request, org string) {
	if org != "" {
		req.Header.Set("snyk-org-name", org)
	}
	// https://www.keycdn.com/blog/http-cache-headers
	req.Header.Set("Cache-Control", "private, max-age=0, no-cache")
	if mustBeEncoded(method) {
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Encoding", "gzip")
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
}

func EncodeIfNeeded(method string, requestBody []byte) (*bytes.Buffer, error) {
	b := new(bytes.Buffer)
	if mustBeEncoded(method) {
		enc := encoding.NewEncoder(b)
		_, err := enc.Write(requestBody)
		if err != nil {
			return nil, err
		}
	} else {
		b = bytes.NewBuffer(requestBody)
	}
	return b, nil
}

func mustBeEncoded(method string) bool {
	return method == http.MethodPost || method == http.MethodPut
}
