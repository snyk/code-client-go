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

//nolint:lll // Some of the lines in this file are going to be long for now.
package codeclient

import (
	"context"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
<<<<<<< HEAD
=======
	"github.com/snyk/code-client-go/config"
	codeClientHTTP "github.com/snyk/code-client-go/http"
	bundle2 "github.com/snyk/code-client-go/internal/bundle"
	"github.com/snyk/code-client-go/internal/deepcode"
>>>>>>> 13ff562 (refactor: move the deepcode package)

	"github.com/snyk/code-client-go/config"
	codeClientHTTP "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/internal/analysis"
	"github.com/snyk/code-client-go/internal/bundle"
	"github.com/snyk/code-client-go/internal/deepcode"
	"github.com/snyk/code-client-go/observability"
	"github.com/snyk/code-client-go/sarif"
)

type codeScanner struct {
	bundleManager bundle.BundleManager
	instrumentor  observability.Instrumentor
	errorReporter observability.ErrorReporter
	logger        *zerolog.Logger
}

type CodeScanner interface {
	UploadAndAnalyze(
		ctx context.Context,
		path string,
		files <-chan string,
		changedFiles map[string]bool,
	) (*sarif.SarifResponse, string, string, error)
}

// NewCodeScanner creates a Code Scanner which can be used to trigger Snyk Code on a folder.
func NewCodeScanner(
	httpClient codeClientHTTP.HTTPClient,
	config config.Config,
	instrumentor observability.Instrumentor,
	errorReporter observability.ErrorReporter,
	logger *zerolog.Logger,
) *codeScanner {
	snykCode := deepcode.NewSnykCodeClient(logger, httpClient, instrumentor, errorReporter, config)
	bundleManager := bundle.NewBundleManager(logger, snykCode, instrumentor, errorReporter)
	return &codeScanner{
		bundleManager: bundleManager,
		instrumentor:  instrumentor,
		errorReporter: errorReporter,
		logger:        logger,
	}
}

// WithBundleManager creates a new Code Scanner from the current one and replaces the bundle manager.
// It can be used to replace the bundle manager in tests.
func (c *codeScanner) WithBundleManager(bundleManager bundle.BundleManager) *codeScanner {
	return &codeScanner{
		bundleManager: bundleManager,
		instrumentor:  c.instrumentor,
		errorReporter: c.errorReporter,
		logger:        c.logger,
	}
}

// UploadAndAnalyze returns a fake SARIF response for testing. Use target-service to run analysis on.
func (c *codeScanner) UploadAndAnalyze(
	ctx context.Context,
	path string,
	files <-chan string,
	changedFiles map[string]bool,
) (*sarif.SarifResponse, string, string, error) {
	if ctx.Err() != nil {
		c.logger.Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
		return nil, "", "", nil
	}

	span := c.instrumentor.StartSpan(ctx, "codeclient.uploadAndAnalyze")
	defer c.instrumentor.Finish(span)

	requestId := span.GetTraceId() // use span trace id as code-request-id
	c.logger.Info().Str("requestId", requestId).Msg("Starting Code analysis.")

	b, err := c.bundleManager.Create(span.Context(), requestId, path, files, changedFiles)
	if err != nil {
		if bundle.IsNoFilesError(err) {
			return nil, "", requestId, nil
		}
		if ctx.Err() == nil { // Only report errors that are not intentional cancellations
			msg := "error creating bundle..."
			c.errorReporter.CaptureError(errors.Wrap(err, msg), observability.ErrorReporterOptions{ErrorDiagnosticPath: path})
			return nil, "", requestId, err
		} else {
			c.logger.Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
			return nil, "", requestId, nil
		}
	}

	uploadedFiles := b.GetFiles()

	b, err = c.bundleManager.Upload(span.Context(), requestId, b, uploadedFiles)

	bundleHash := b.GetBundleHash()
	if err != nil {
		if ctx.Err() != nil { // Only handle errors that are not intentional cancellations
			msg := "error uploading files..."
			c.errorReporter.CaptureError(errors.Wrap(err, msg), observability.ErrorReporterOptions{ErrorDiagnosticPath: path})
			return nil, bundleHash, requestId, err
		} else {
			log.Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
			return nil, bundleHash, requestId, nil
		}
	}

	if bundleHash == "" {
		c.logger.Info().Msg("empty bundle, no Snyk Code analysis")
		return nil, bundleHash, requestId, nil
	}

	response, err := analysis.RunAnalysis()
	if ctx.Err() != nil {
		c.logger.Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
		return nil, bundleHash, requestId, nil
	}

	return response, bundleHash, requestId, err
}
