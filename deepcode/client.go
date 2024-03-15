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
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	codeClientHTTP "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/observability"
)

//go:generate mockgen -destination=mocks/client.go -source=client.go -package mocks
type SnykCodeClient interface {
	GetFilters(ctx context.Context, host string) (
		filters FiltersResponse,
		err error)

	CreateBundle(
		ctx context.Context,
		host string,
		files map[string]string,
	) (newBundleHash string, missingFiles []string, err error)

	ExtendBundle(
		ctx context.Context,
		host string,
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
	engine       workflow.Engine
	logger       *zerolog.Logger
}

func NewSnykCodeClient(
	engine workflow.Engine,
	httpClient codeClientHTTP.HTTPClient,
	instrumentor observability.Instrumentor,
) *snykCodeClient {
	logger := engine.GetLogger()
	return &snykCodeClient{httpClient, instrumentor, engine, logger}
}

func (s *snykCodeClient) GetFilters(ctx context.Context, snykCodeApiUrl string) (
	filters FiltersResponse,
	err error,
) {
	method := "code.GetFilters"
	log := s.logger.With().Str("method", method).Logger()
	log.Debug().Msg("API: Getting file extension filters")

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	c := s.engine.GetConfiguration()

	host, err := s.FormatCodeApiURL(snykCodeApiUrl)
	if err != nil {
		return FiltersResponse{ConfigFiles: nil, Extensions: nil}, err
	}

	responseBody, err := s.httpClient.DoCall(span.Context(), c, host, "GET", "/filters", nil)
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
	snykCodeApiUrl string,
	filesToFilehashes map[string]string,
) (string, []string, error) {
	method := "code.CreateBundle"
	log := s.logger.With().Str("method", method).Logger()
	log.Debug().Msg("API: Creating bundle for " + strconv.Itoa(len(filesToFilehashes)) + " files")

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	requestBody, err := json.Marshal(filesToFilehashes)
	if err != nil {
		return "", nil, err
	}

	c := s.engine.GetConfiguration()

	host, err := s.FormatCodeApiURL(snykCodeApiUrl)
	if err != nil {
		return "", nil, err
	}

	responseBody, err := s.httpClient.DoCall(span.Context(), c, host, "POST", "/bundle", requestBody)
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
	snykCodeApiUrl string,
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

	requestBody, err := json.Marshal(ExtendBundleRequest{
		Files:        files,
		RemovedFiles: removedFiles,
	})
	if err != nil {
		return "", nil, err
	}

	c := s.engine.GetConfiguration()

	host, err := s.FormatCodeApiURL(snykCodeApiUrl)
	if err != nil {
		return "", nil, err
	}

	responseBody, err := s.httpClient.DoCall(span.Context(), c, host, "PUT", "/bundle/"+bundleHash, requestBody)
	if err != nil {
		return "", nil, err
	}
	var bundleResponse BundleResponse
	err = json.Unmarshal(responseBody, &bundleResponse)
	return bundleResponse.BundleHash, bundleResponse.MissingFiles, err
}

var codeApiRegex = regexp.MustCompile(`^(deeproxy\.)?`)

// This is only exported for tests.
func (s *snykCodeClient) FormatCodeApiURL(snykCodeApiUrl string) (string, error) {
	config := s.engine.GetConfiguration()

	if !config.GetBool(configuration.IS_FEDRAMP) {
		return snykCodeApiUrl, nil
	}
	u, err := url.Parse(snykCodeApiUrl)
	if err != nil {
		return "", err
	}

	u.Host = codeApiRegex.ReplaceAllString(u.Host, "api.")

	organization := config.GetString(configuration.ORGANIZATION)
	if organization == "" {
		return "", errors.New("Organization is required in a fedramp environment")
	}

	u.Path = "/hidden/orgs/" + organization + "/code"

	return u.String(), nil
}
