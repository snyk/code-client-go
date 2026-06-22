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

package sanitizers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/code-client-go/internal/analysis/sanitizers"
)

func TestDecodeDocument_valid(t *testing.T) {
	doc, err := sanitizers.DecodeDocument(strings.NewReader(
		`{"scan_id":"fp","candidates":[{"kind":"sanitizer","fqn":"app.security.clean"}]}`))
	require.NoError(t, err)
	assert.Equal(t, "fp", doc.ScanID)
	require.Len(t, doc.Candidates, 1)
	assert.Equal(t, "app.security.clean", doc.Candidates[0].FQN)
}

func TestDecodeDocument_emptyCandidatesIsValid(t *testing.T) {
	doc, err := sanitizers.DecodeDocument(strings.NewReader(`{"candidates":[]}`))
	require.NoError(t, err)
	assert.Empty(t, doc.Candidates)
}

func TestDecodeDocument_missingFQNErrors(t *testing.T) {
	_, err := sanitizers.DecodeDocument(strings.NewReader(
		`{"candidates":[{"kind":"sanitizer"}]}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no fqn")
}

func TestDecodeDocument_malformedErrors(t *testing.T) {
	_, err := sanitizers.DecodeDocument(strings.NewReader(`{not json`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
}

func TestFetchDiscoveryDocument_success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"scan_id":"fp","candidates":[{"kind":"sanitizer","fqn":"app.security.clean"}]}`))
	}))
	defer srv.Close()

	doc, err := sanitizers.FetchDiscoveryDocument(context.Background(), srv.Client(), srv.URL)
	require.NoError(t, err)
	require.Len(t, doc.Candidates, 1)
	assert.Equal(t, "app.security.clean", doc.Candidates[0].FQN)
}

func TestFetchDiscoveryDocument_non200Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := sanitizers.FetchDiscoveryDocument(context.Background(), srv.Client(), srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestFetchDiscoveryDocument_emptyURLErrors(t *testing.T) {
	_, err := sanitizers.FetchDiscoveryDocument(context.Background(), http.DefaultClient, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "findings URL")
}
