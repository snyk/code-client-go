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
	httpClient   codeClientHTTP.HTTPClient
	instrumentor observability.Instrumentor
	logger       *zerolog.Logger
	config       config.Config
}

func NewSnykCodeClient(
	logger *zerolog.Logger,
	httpClient codeClientHTTP.HTTPClient,
	instrumentor observability.Instrumentor,
	config config.Config,
) *snykCodeClient {
	return &snykCodeClient{httpClient, instrumentor, logger, config}
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

	responseBody, err := s.httpClient.DoCall(span.Context(), host, s.headers("GET"), "GET", "/filters", bytes.NewBufferString(""))
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

	var bodyBuffer *bytes.Buffer
	bodyBuffer, err = s.encodeIfNeeded(method, requestBody)
	if err != nil {
		return "", nil, err
	}

	responseBody, err := s.httpClient.DoCall(span.Context(), host, s.headers("POST"), "POST", "/bundle", bodyBuffer)
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

	var bodyBuffer *bytes.Buffer
	bodyBuffer, err = s.encodeIfNeeded(method, requestBody)
	if err != nil {
		return "", nil, err
	}

	responseBody, err := s.httpClient.DoCall(span.Context(), host, s.headers("PUT"), "PUT", "/bundle/"+bundleHash, bodyBuffer)
	if err != nil {
		return "", nil, err
	}
	var bundleResponse BundleResponse
	err = json.Unmarshal(responseBody, &bundleResponse)
	return bundleResponse.BundleHash, bundleResponse.MissingFiles, err
}

func (s *snykCodeClient) headers(method string) map[string]string {
	headers := map[string]string{}
	// Setting a chosen org name for the request
	org := s.config.Organization()
	if org != "" {
		headers["snyk-org-name"] = org
	}
	// https://www.keycdn.com/blog/http-cache-headers
	headers["Cache-Control"] = "private, max-age=0, no-cache"
	if s.mustBeEncoded(method) {
		headers["Content-Type"] = "application/octet-stream"
		headers["Content-Encoding"] = "gzip"
	} else {
		headers["Content-Type"] = "application/json"
	}
	return headers
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
