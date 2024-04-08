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
type SnykCodeClient interface {
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

type snykCodeClient struct {
	httpClient    codeClientHTTP.HTTPClient
	instrumentor  observability.Instrumentor
	errorReporter observability.ErrorReporter
	logger        *zerolog.Logger
	config        config.Config
}

func NewSnykCodeClient(
	logger *zerolog.Logger,
	httpClient codeClientHTTP.HTTPClient,
	instrumentor observability.Instrumentor,
	errorReporter observability.ErrorReporter,
	config config.Config,
) *snykCodeClient {
	return &snykCodeClient{httpClient, instrumentor, errorReporter, logger, config}
}

func (s *snykCodeClient) GetFilters(ctx context.Context) (
	filters FiltersResponse,
	err error,
) {
	method := "code.GetFilters"
	log := s.logger.With().Str("method", method).Logger()
	log.Debug().Msg("API: Getting file extension filters")

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	host, err := s.Host()
	if err != nil {
		return FiltersResponse{ConfigFiles: nil, Extensions: nil}, err
	}

	responseBody, err := s.Request(host, http.MethodGet, "/filters", nil)
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

func (s *snykCodeClient) CreateBundle(
	ctx context.Context,
	filesToFilehashes map[string]string,
) (string, []string, error) {
	method := "code.CreateBundle"
	log := s.logger.With().Str("method", method).Logger()
	log.Debug().Msg("API: Creating bundle for " + strconv.Itoa(len(filesToFilehashes)) + " files")

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	host, err := s.Host()
	if err != nil {
		return "", nil, err
	}

	requestBody, err := json.Marshal(filesToFilehashes)
	if err != nil {
		return "", nil, err
	}

	responseBody, err := s.Request(host, http.MethodPost, "/bundle", requestBody)
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

func (s *snykCodeClient) ExtendBundle(
	ctx context.Context,
	bundleHash string,
	files map[string]BundleFile,
	removedFiles []string,
) (string, []string, error) {
	method := "code.ExtendBundle"
	log := s.logger.With().Str("method", method).Logger()
	log.Debug().Msg("API: Extending bundle for " + strconv.Itoa(len(files)) + " files")
	defer log.Debug().Str("method", method).Msg("API: Extend done")

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	host, err := s.Host()
	if err != nil {
		return "", nil, err
	}

	requestBody, err := json.Marshal(ExtendBundleRequest{
		Files:        files,
		RemovedFiles: removedFiles,
	})
	if err != nil {
		return "", nil, err
	}

	responseBody, err := s.Request(host, http.MethodPut, "/bundle/"+bundleHash, requestBody)
	if err != nil {
		return "", nil, err
	}
	var bundleResponse BundleResponse
	err = json.Unmarshal(responseBody, &bundleResponse)
	return bundleResponse.BundleHash, bundleResponse.MissingFiles, err
}

// This is only exported for tests.
func (s *snykCodeClient) Host() (string, error) {
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

func (s *snykCodeClient) Request(
	host string,
	method string,
	path string,
	requestBody []byte,
) ([]byte, error) {
	log := s.logger.With().Str("method", "deepcode.Request").Logger()

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
	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Error().Err(closeErr).Msg("Couldn't close response body in call to Snyk Code")
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

func (s *snykCodeClient) addHeaders(method string, req *http.Request) {
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

func (s *snykCodeClient) encodeIfNeeded(method string, requestBody []byte) (*bytes.Buffer, error) {
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

func (s *snykCodeClient) mustBeEncoded(method string) bool {
	return method == http.MethodPost || method == http.MethodPut
}
