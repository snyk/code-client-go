/*
 * © 2026 Snyk Limited All rights reserved.
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

package sanitizers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	errors "github.com/pkg/errors"
)

// CandidatesFoundError signals that discovery surfaced one or more candidates.
// Callers should exit with code 1 (aibom convention: findings present).
type CandidatesFoundError struct {
	Count int
}

func (e *CandidatesFoundError) Error() string {
	return "custom-sanitizer candidates found"
}

// DecodeDocument decodes a candidate findings document (Appendix-A shape) and
// validates it. An empty candidate set is valid — discovery on safe code
// surfaces nothing — but every candidate must carry an FQN.
func DecodeDocument(r io.Reader) (*Document, error) {
	var doc Document
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, errors.Wrap(err, "failed to decode candidate document")
	}
	for i, c := range doc.Candidates {
		if c.FQN == "" {
			return nil, errors.Errorf("candidate %d has no fqn", i)
		}
	}
	return &doc, nil
}

// FetchDiscoveryDocument GETs a completed discovery findings document and decodes it.
func FetchDiscoveryDocument(ctx context.Context, httpClient interface {
	Do(*http.Request) (*http.Response, error)
}, findingsURL string) (*Document, error) {
	if findingsURL == "" {
		return nil, errors.New("do not have a findings URL")
	}
	req, err := http.NewRequest(http.MethodGet, findingsURL, nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)

	rsp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rsp.Body.Close() }()

	if rsp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("failed to retrieve candidates from findings URL: status %d", rsp.StatusCode)
	}
	return DecodeDocument(rsp.Body)
}
