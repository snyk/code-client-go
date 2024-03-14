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
	"strconv"

	"github.com/rs/zerolog/log"
	codeClientHTTP "github.com/snyk/code-client-go/internal/http"
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
}

func NewSnykCodeClient(
	httpClient codeClientHTTP.HTTPClient,
	instrumentor observability.Instrumentor,
) SnykCodeClient {
	return &snykCodeClient{httpClient, instrumentor}
}

func (s *snykCodeClient) GetFilters(ctx context.Context) (
	filters FiltersResponse,
	err error,
) {
	method := "code.GetFilters"
	log.Debug().Str("method", method).Msg("API: Getting file extension filters")

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	responseBody, err := s.httpClient.DoCall(span.Context(), "GET", "/filters", nil)
	if err != nil {
		return FiltersResponse{ConfigFiles: nil, Extensions: nil}, err
	}

	err = json.Unmarshal(responseBody, &filters)
	if err != nil {
		return FiltersResponse{ConfigFiles: nil, Extensions: nil}, err
	}
	log.Debug().Str("method", method).Msg("API: Finished getting filters")
	return filters, nil
}

func (s *snykCodeClient) CreateBundle(
	ctx context.Context,
	filesToFilehashes map[string]string,
) (string, []string, error) {
	method := "code.CreateBundle"
	log.Debug().Str("method", method).Msg("API: Creating bundle for " + strconv.Itoa(len(filesToFilehashes)) + " files")

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	requestBody, err := json.Marshal(filesToFilehashes)
	if err != nil {
		return "", nil, err
	}

	responseBody, err := s.httpClient.DoCall(span.Context(), "POST", "/bundle", requestBody)
	if err != nil {
		return "", nil, err
	}

	var bundle BundleResponse
	err = json.Unmarshal(responseBody, &bundle)
	if err != nil {
		return "", nil, err
	}
	log.Debug().Str("method", method).Msg("API: Create done")
	return bundle.BundleHash, bundle.MissingFiles, nil
}

func (s *snykCodeClient) ExtendBundle(
	ctx context.Context,
	bundleHash string,
	files map[string]BundleFile,
	removedFiles []string,
) (string, []string, error) {
	method := "code.ExtendBundle"
	log.Debug().Str("method", method).Msg("API: Extending bundle for " + strconv.Itoa(len(files)) + " files")
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

	responseBody, err := s.httpClient.DoCall(span.Context(), "PUT", "/bundle/"+bundleHash, requestBody)
	if err != nil {
		return "", nil, err
	}
	var bundleResponse BundleResponse
	err = json.Unmarshal(responseBody, &bundleResponse)
	return bundleResponse.BundleHash, bundleResponse.MissingFiles, err
}
