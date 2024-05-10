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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/snyk/code-client-go/config"
	"github.com/snyk/code-client-go/internal/util/encoding"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"github.com/rs/zerolog"

	codeClientHTTP "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/observability"
)

//go:generate mockgen -destination=mocks/client.go -source=client.go -package mocks
type DeepcodeClient interface {
	GetFilters(ctx context.Context) (
		filters FiltersResponse,
		err error)

	CreateBundle(
		ctx context.Context,
		files map[string]string,
	) (newBundleHash string, missingFiles []string, err error)

	ExtendBundle(
		ctx context.Context,
		bundleHash string,
		files map[string]BundleFile,
		removedFiles []string,
	) (newBundleHash string, missingFiles []string, err error)
}

type FiltersResponse struct {
	ConfigFiles []string `json:"configFiles" pact:"min=1"`
	Extensions  []string `json:"extensions" pact:"min=1"`
}

type ExtendBundleRequest struct {
	Files        map[string]BundleFile `json:"files"`
	RemovedFiles []string              `json:"removedFiles,omitempty"`
}

type BundleResponse struct {
	BundleHash   string   `json:"bundleHash"`
	MissingFiles []string `json:"missingFiles"`
}

type deepcodeClient struct {
	httpClient    codeClientHTTP.HTTPClient
	instrumentor  observability.Instrumentor
	errorReporter observability.ErrorReporter
	logger        *zerolog.Logger
	config        config.Config
}

func NewDeepcodeClient(
	config config.Config,
	httpClient codeClientHTTP.HTTPClient,
	logger *zerolog.Logger,
	instrumentor observability.Instrumentor,
	errorReporter observability.ErrorReporter,
) *deepcodeClient {
	return &deepcodeClient{
		httpClient,
		instrumentor,
		errorReporter,
		logger,
		config,
	}
}

func (s *deepcodeClient) GetFilters(ctx context.Context) (
	filters FiltersResponse,
	err error,
) {
	method := "deepcode.GetFilters"
	log := s.logger.With().Str("method", method).Logger()
	log.Debug().Msg("API: Getting file extension filters")

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	responseBody, err := s.Request(http.MethodGet, "/filters", nil)
	if err != nil {
		return FiltersResponse{ConfigFiles: nil, Extensions: nil}, err
	}

	err = json.Unmarshal(responseBody, &filters)
	if err != nil {
		return FiltersResponse{ConfigFiles: nil, Extensions: nil}, err
	}
	log.Debug().Msg("API: Finished getting filters")
	return filters, nil
}

func (s *deepcodeClient) CreateBundle(
	ctx context.Context,
	filesToFilehashes map[string]string,
) (string, []string, error) {
	method := "deepcode.CreateBundle"
	log := s.logger.With().Str("method", method).Logger()
	log.Debug().Msg("API: Creating bundle for " + strconv.Itoa(len(filesToFilehashes)) + " files")

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	requestBody, err := json.Marshal(filesToFilehashes)
	if err != nil {
		return "", nil, err
	}

	responseBody, err := s.Request(http.MethodPost, "/bundle", requestBody)
	if err != nil {
		return "", nil, err
	}

	var bundle BundleResponse
	err = json.Unmarshal(responseBody, &bundle)
	if err != nil {
		return "", nil, err
	}
	log.Debug().Msg("API: Create done")
	return bundle.BundleHash, bundle.MissingFiles, nil
}

func (s *deepcodeClient) ExtendBundle(
	ctx context.Context,
	bundleHash string,
	files map[string]BundleFile,
	removedFiles []string,
) (string, []string, error) {
	method := "deepcode.ExtendBundle"
	log := s.logger.With().Str("method", method).Logger()
	log.Debug().Msg("API: Extending bundle for " + strconv.Itoa(len(files)) + " files")
	defer log.Debug().Str("method", method).Msg("API: Extend done")

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	requestBody, err := json.Marshal(ExtendBundleRequest{
		Files:        files,
		RemovedFiles: removedFiles,
	})
	if err != nil {
		return "", nil, err
	}

	responseBody, err := s.Request(http.MethodPut, "/bundle/"+bundleHash, requestBody)
	if err != nil {
		return "", nil, err
	}
	var bundleResponse BundleResponse
	err = json.Unmarshal(responseBody, &bundleResponse)
	return bundleResponse.BundleHash, bundleResponse.MissingFiles, err
}

// This is only exported for tests.
func (s *deepcodeClient) Host() (string, error) {
	var codeApiRegex = regexp.MustCompile(`^(deeproxy\.)?`)

	snykCodeApiUrl := s.config.SnykCodeApi()
	if !s.config.IsFedramp() {
		return snykCodeApiUrl, nil
	}
	u, err := url.Parse(snykCodeApiUrl)
	if err != nil {
		return "", err
	}

	u.Host = codeApiRegex.ReplaceAllString(u.Host, "api.")

	organization := s.config.Organization()
	if organization == "" {
		return "", errors.New("Organization is required in a fedramp environment")
	}

	u.Path = "/hidden/orgs/" + organization + "/code"

	return u.String(), nil
}

func (s *deepcodeClient) Request(
	method string,
	path string,
	requestBody []byte,
) ([]byte, error) {
	log := s.logger.With().Str("method", "deepcode.Request").Logger()

	host, err := s.Host()
	if err != nil {
		return nil, err
	}

	s.logger.Trace().Str("requestBody", string(requestBody)).Msg("SEND TO REMOTE")

	bodyBuffer, err := s.encodeIfNeeded(method, requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, host+path, bodyBuffer)
	if err != nil {
		return nil, err
	}

	s.addHeaders(method, req)

	response, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	err = s.checkResponseCode(response)
	if err != nil {
		return nil, err
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			log.Error().Err(closeErr).Msg("Couldn't close response body in call to Snyk Code")
		}
	}()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		log.Error().Err(err).Msg("error reading response body")
		s.errorReporter.CaptureError(err, observability.ErrorReporterOptions{ErrorDiagnosticPath: req.RequestURI})
		return nil, err
	}

	return responseBody, nil
}

func (s *deepcodeClient) addHeaders(method string, req *http.Request) {
	// Setting a chosen org name for the request
	org := s.config.Organization()
	if org != "" {
		req.Header.Set("snyk-org-name", org)
	}
	// https://www.keycdn.com/blog/http-cache-headers
	req.Header.Set("Cache-Control", "private, max-age=0, no-cache")
	if s.mustBeEncoded(method) {
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Encoding", "gzip")
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
}

func (s *deepcodeClient) encodeIfNeeded(method string, requestBody []byte) (*bytes.Buffer, error) {
	b := new(bytes.Buffer)
	mustBeEncoded := s.mustBeEncoded(method)
	if mustBeEncoded {
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

func (s *deepcodeClient) mustBeEncoded(method string) bool {
	return method == http.MethodPost || method == http.MethodPut
}

func (s *deepcodeClient) checkResponseCode(r *http.Response) error {
	if r.StatusCode >= 200 && r.StatusCode <= 299 {
		return nil
	}
	return fmt.Errorf("Unexpected response code: %s", r.Status)
}
