/*
 * © 2025 Snyk Limited All rights reserved.
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

//nolint:lll // Some of the lines in this file are going to be long for now.
package analysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"

	"github.com/snyk/code-client-go/scan"

	codeClientHTTP "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/sarif"
)

// Legacy analysis types and constants
const (
	StatusComplete  = "COMPLETE"
	StatusFailed    = "FAILED"
	StatusAnalyzing = "ANALYZING"
)

type RequestKey struct {
	Type         string   `json:"type"`
	Hash         string   `json:"hash"`
	LimitToFiles []string `json:"limitToFiles,omitempty"`
	Shard        string   `json:"shard"`
}

type requestContextOrg struct {
	Name        string          `json:"name"`
	DisplayName string          `json:"displayName"`
	PublicId    string          `json:"publicId"`
	Flags       map[string]bool `json:"flags"`
}

type requestContext struct {
	Initiator string            `json:"initiator"`
	Flow      string            `json:"flow,omitempty"`
	Org       requestContextOrg `json:"org,omitempty"`
}

type Request struct {
	Key             RequestKey     `json:"key"`
	Severity        int            `json:"severity,omitempty"`
	Prioritized     bool           `json:"prioritized,omitempty"`
	Legacy          bool           `json:"legacy"`
	AnalysisContext requestContext `json:"analysisContext"`
}

type FailedError struct {
	Msg string
}

func (e FailedError) Error() string { return e.Msg }

// Legacy analysis helper functions
func (a *analysisOrchestrator) newRequestContext() requestContext {
	unknown := "unknown"
	orgId := unknown
	if a.config.Organization() != "" {
		orgId = a.config.Organization()
	}

	return requestContext{
		Initiator: "IDE",
		Flow:      "language-server",
		Org: requestContextOrg{
			Name:        unknown,
			DisplayName: unknown,
			PublicId:    orgId,
		},
	}
}

func (a *analysisOrchestrator) createRequestBody(bundleHash, shardKey string, limitToFiles []string, severity int) ([]byte, error) {
	request := Request{
		Key: RequestKey{
			Type:         "file",
			Hash:         bundleHash,
			LimitToFiles: limitToFiles,
		},
		Legacy:          false,
		AnalysisContext: a.newRequestContext(),
	}
	if len(shardKey) > 0 {
		request.Key.Shard = shardKey
	}
	if severity > 0 {
		request.Severity = severity
	}

	requestBody, err := json.Marshal(request)
	return requestBody, err
}

func (a *analysisOrchestrator) getCodeApiUrl() (string, error) {
	// Use the same logic as the original SnykCodeHTTPClient
	if !a.config.IsFedramp() {
		return a.config.SnykCodeApi(), nil
	}
	u, err := url.Parse(a.config.SnykCodeApi())
	if err != nil {
		return "", err
	}

	// Apply fedramp transformation (this might need adjustment based on the actual requirements)
	u.Host = strings.Replace(u.Host, "deeproxy", "api", 1)

	if a.config.Organization() == "" {
		return "", errors.New("organization is required in a fedramp environment")
	}

	u.Path = "/hidden/orgs/" + a.config.Organization() + "/code"
	return u.String(), nil
}

func (a *analysisOrchestrator) RunLegacyTest(ctx context.Context, bundleHash string, shardKey string, limitToFiles []string, severity int) (*sarif.SarifResponse, scan.LegacyScanStatus, error) {
	method := "analysis.RunLegacyTest"
	span := a.instrumentor.StartSpan(ctx, method)
	defer a.instrumentor.Finish(span)

	a.logger.Debug().Str("method", method).Str("bundleHash", bundleHash).Msg("API: Retrieving analysis for bundle")
	defer a.logger.Debug().Str("method", method).Str("bundleHash", bundleHash).Msg("API: Retrieving analysis done")

	requestBody, err := a.createRequestBody(bundleHash, shardKey, limitToFiles, severity)
	if err != nil {
		a.logger.Err(err).Str("method", method).Str("requestBody", string(requestBody)).Msg("error creating request body")
		return nil, scan.LegacyScanStatus{}, err
	}

	// Get the legacy code API URL
	baseUrl, err := a.getCodeApiUrl()
	if err != nil {
		return nil, scan.LegacyScanStatus{}, err
	}

	// Create HTTP request
	analysisUrl := baseUrl + "/analysis"
	req, err := http.NewRequestWithContext(span.Context(), http.MethodPost, analysisUrl, bytes.NewBuffer(requestBody))
	if err != nil {
		a.logger.Err(err).Str("method", method).Msg("error creating HTTP request")
		return nil, scan.LegacyScanStatus{}, err
	}
	codeClientHTTP.AddDefaultHeaders(req, span.GetTraceId(), a.config.Organization())

	// Make HTTP call
	resp, err := a.httpClient.Do(req)
	failed := scan.LegacyScanStatus{Message: StatusFailed}
	if err != nil {
		a.logger.Err(err).Str("method", method).Msg("error response from analysis")
		return nil, failed, err
	}
	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			a.logger.Err(closeErr).Msg("failed to close response body")
		}
	}()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		a.logger.Err(err).Str("method", method).Msg("error reading response body")
		return nil, failed, err
	}

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		a.logger.Err(err).Str("method", method).Str("responseBody", string(responseBody)).Int("statusCode", resp.StatusCode).Msg("error response from analysis")
		return nil, failed, FailedError{Msg: string(responseBody)}
	}

	var response sarif.SarifResponse
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		a.logger.Err(err).Str("method", method).Str("responseBody", string(responseBody)).Msg("error unmarshalling")
		return nil, failed, err
	} else {
		a.logger.Debug().
			Str("method", method).
			Str("status", response.Status).
			Float64("progress", response.Progress).
			Int("fetchingCodeTime", response.Timing.FetchingCode).
			Int("analysisTime", response.Timing.Analysis).
			Int("filesAnalyzed", len(response.Coverage)).
			Msg("Received response summary")
	}

	a.logger.Debug().Str("method", method).Str("bundleHash", bundleHash).Float64("progress",
		response.Progress).Msgf("LegacyScanStatus: %s", response.Status)

	if response.Status == failed.Message {
		a.logger.Err(err).Str("method", method).Str("responseStatus", response.Status).Msg("analysis failed")
		return nil, failed, FailedError{Msg: string(responseBody)}
	}

	if response.Status == "" {
		a.logger.Err(err).Str("method", method).Str("responseStatus", response.Status).Msg("unknown response status (empty)")
		return nil, failed, FailedError{Msg: string(responseBody)}
	}

	status := scan.LegacyScanStatus{Message: response.Status, Percentage: int(math.RoundToEven(response.Progress * 100))}
	if response.Status != StatusComplete {
		return nil, status, nil
	}

	return &response, status, nil
}
