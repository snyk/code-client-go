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
	"github.com/rs/zerolog/log"

	"github.com/snyk/code-client-go/bundle"
	"github.com/snyk/code-client-go/internal/analysis"
	"github.com/snyk/code-client-go/observability"
	"github.com/snyk/code-client-go/sarif"
)

type codeScanner struct {
	bundleManager bundle.BundleManager
	instrumentor  observability.Instrumentor
	errorReporter observability.ErrorReporter
	analytics     observability.Analytics
}

type CodeScanner interface {
	UploadAndAnalyze(
		ctx context.Context,
		files <-chan string,
		path string,
		changedFiles map[string]bool,
		scanMetrics observability.ScanMetrics,
	) (*sarif.SarifResponse, *bundle.Bundle, error)
}

// NewCodeScanner creates a Code Scanner which can be used to trigger Snyk Code on a folder.
func NewCodeScanner(
	bundleManager bundle.BundleManager,
	instrumentor observability.Instrumentor,
	errorReporter observability.ErrorReporter,
	analytics observability.Analytics,
) *codeScanner {
	return &codeScanner{
		bundleManager: bundleManager,
		instrumentor:  instrumentor,
		errorReporter: errorReporter,
		analytics:     analytics,
	}
}

// TODO: try out in snyk-ls
// UploadAndAnalyze returns a fake SARIF response for testing. Use target-service to run analysis on.
func (c *codeScanner) UploadAndAnalyze(
	ctx context.Context,
	files <-chan string,
	path string,
	changedFiles map[string]bool,
	scanMetrics observability.ScanMetrics,
) (*sarif.SarifResponse, bundle.Bundle, error) {
	if ctx.Err() != nil {
		log.Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
		return nil, nil, nil
	}

	span := c.instrumentor.StartSpan(ctx, "code.uploadAndAnalyze")
	defer c.instrumentor.Finish(span)

	requestId := span.GetTraceId() // use span trace id as code-request-id
	log.Info().Str("RequestId", requestId).Msg("Starting Code analysis.")

	b, err := c.bundleManager.Create(span.Context(), requestId, path, files, changedFiles)
	if err != nil {
		if bundle.IsNoFilesError(err) {
			return nil, nil, nil
		}
		if ctx.Err() == nil { // Only report errors that are not intentional cancellations
			msg := "error creating bundle..."
			c.errorReporter.CaptureError(errors.Wrap(err, msg), observability.ErrorReporterOptions{ErrorDiagnosticPath: path})
			c.analytics.TrackScan(err == nil, scanMetrics)
			return nil, nil, err
		} else {
			log.Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
			return nil, nil, nil
		}
	}

	uploadedFiles := b.GetFiles()
	scanMetrics.SetLastScanFileCount(len(uploadedFiles))

	b, err = c.bundleManager.Upload(span.Context(), b, uploadedFiles)
	// TODO LSP error handling should be pushed UP to the LSP layer
	if err != nil {
		if ctx.Err() != nil { // Only handle errors that are not intentional cancellations
			msg := "error uploading files..."
			c.errorReporter.CaptureError(errors.Wrap(err, msg), observability.ErrorReporterOptions{ErrorDiagnosticPath: path})
			c.analytics.TrackScan(err == nil, scanMetrics)
			return nil, b, err
		} else {
			log.Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
			return nil, b, nil
		}
	}

	if b.GetBundleHash() == "" {
		log.Info().Msg("empty bundle, no Snyk Code analysis")
		return nil, b, nil
	}

	response, err := analysis.RunAnalysis()
	if ctx.Err() != nil {
		log.Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
		return nil, nil, nil
	}

	c.analytics.TrackScan(err == nil, scanMetrics)
	return response, b, nil
}
