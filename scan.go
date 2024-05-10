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

	"github.com/snyk/code-client-go/config"
	codeClientHTTP "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/internal/analysis"
	"github.com/snyk/code-client-go/internal/bundle"
	"github.com/snyk/code-client-go/internal/deepcode"
	"github.com/snyk/code-client-go/observability"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
)

type codeScanner struct {
	httpClient           codeClientHTTP.HTTPClient
	bundleManager        bundle.BundleManager
	analysisOrchestrator analysis.AnalysisOrchestrator
	instrumentor         observability.Instrumentor
	errorReporter        observability.ErrorReporter
	logger               *zerolog.Logger
	config               config.Config
}

type CodeScanner interface {
	UploadAndAnalyze(
		ctx context.Context,
		requestId string,
		target scan.Target,
		files <-chan string,
		changedFiles map[string]bool,
	) (*sarif.SarifResponse, string, error)
}

var _ CodeScanner = &codeScanner{}

type OptionFunc func(*codeScanner)

func WithInstrumentor(instrumentor observability.Instrumentor) OptionFunc {
	return func(c *codeScanner) {
		c.instrumentor = instrumentor
		c.initDeps(c.httpClient)
	}
}

func WithErrorReporter(errorReporter observability.ErrorReporter) OptionFunc {
	return func(c *codeScanner) {
		c.errorReporter = errorReporter
		c.initDeps(c.httpClient)
	}
}

func WithLogger(logger *zerolog.Logger) OptionFunc {
	return func(c *codeScanner) {
		c.logger = logger
		c.initDeps(c.httpClient)
	}
}

func (c *codeScanner) initDeps(
	httpClient codeClientHTTP.HTTPClient,
) {
	deepcodeClient := deepcode.NewDeepcodeClient(c.config, httpClient, c.logger, c.instrumentor, c.errorReporter)
	bundleManager := bundle.NewBundleManager(deepcodeClient, c.logger, c.instrumentor, c.errorReporter)
	c.bundleManager = bundleManager
	analysisOrchestrator := analysis.NewAnalysisOrchestrator(c.config, c.logger, httpClient, c.instrumentor, c.errorReporter)
	c.analysisOrchestrator = analysisOrchestrator
}

// NewCodeScanner creates a Code Scanner which can be used to trigger Snyk Code on a folder.
func NewCodeScanner(
	config config.Config,
	httpClient codeClientHTTP.HTTPClient,
	options ...OptionFunc,
) *codeScanner {
	nopLogger := zerolog.Nop()
	instrumentor := observability.NewInstrumentor()
	errorReporter := observability.NewErrorReporter(&nopLogger)

	scanner := &codeScanner{
		httpClient:    httpClient,
		errorReporter: errorReporter,
		logger:        &nopLogger,
		instrumentor:  instrumentor,
		config:        config,
	}

	// initialize other dependencies with the default
	scanner.initDeps(httpClient)

	for _, option := range options {
		option(scanner)
	}

	return scanner
}

// WithBundleManager creates a new Code Scanner from the current one and replaces the bundle manager.
// It can be used to replace the bundle manager in tests.
func (c *codeScanner) WithBundleManager(bundleManager bundle.BundleManager) *codeScanner {
	return &codeScanner{
		bundleManager:        bundleManager,
		analysisOrchestrator: c.analysisOrchestrator,
		errorReporter:        c.errorReporter,
		logger:               c.logger,
		config:               c.config,
	}
}

// WithAnalysisOrchestrator creates a new Code Scanner from the current one and replaces the analysis orchestrator.
// It can be used to replace the analysis orchestrator in tests.
func (c *codeScanner) WithAnalysisOrchestrator(analysisOrchestrator analysis.AnalysisOrchestrator) *codeScanner {
	return &codeScanner{
		bundleManager:        c.bundleManager,
		analysisOrchestrator: analysisOrchestrator,
		errorReporter:        c.errorReporter,
		logger:               c.logger,
		config:               c.config,
	}
}

// UploadAndAnalyze returns a fake SARIF response for testing. Use target-service to run analysis on.
func (c *codeScanner) UploadAndAnalyze(
	ctx context.Context,
	requestId string,
	target scan.Target,
	files <-chan string,
	changedFiles map[string]bool,
) (*sarif.SarifResponse, string, error) {
	if ctx.Err() != nil {
		c.logger.Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
		return nil, "", nil
	}

	if ctx.Err() != nil {
		c.logger.Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
		return nil, "", nil
	}
	b, err := c.bundleManager.Create(ctx, requestId, target.GetPath(), files, changedFiles)
	if err != nil {
		if bundle.IsNoFilesError(err) {
			return nil, "", nil
		}
		if ctx.Err() == nil { // Only report errors that are not intentional cancellations
			msg := "error creating bundle..."
			c.errorReporter.CaptureError(errors.Wrap(err, msg), observability.ErrorReporterOptions{ErrorDiagnosticPath: target.GetPath()})
			return nil, "", err
		} else {
			c.logger.Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
			return nil, "", nil
		}
	}

	uploadedFiles := b.GetFiles()

	b, err = c.bundleManager.Upload(ctx, requestId, b, uploadedFiles)
	bundleHash := b.GetBundleHash()
	if err != nil {
		if ctx.Err() != nil { // Only handle errors that are not intentional cancellations
			msg := "error uploading files..."
			c.errorReporter.CaptureError(errors.Wrap(err, msg), observability.ErrorReporterOptions{ErrorDiagnosticPath: target.GetPath()})
			return nil, bundleHash, err
		} else {
			c.logger.Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
			return nil, bundleHash, nil
		}
	}

	if bundleHash == "" {
		c.logger.Info().Msg("empty bundle, no Snyk Code analysis")
		return nil, bundleHash, nil
	}

	workspaceId, err := c.analysisOrchestrator.CreateWorkspace(ctx, c.config.Organization(), requestId, target, bundleHash)
	if err != nil {
		if ctx.Err() == nil { // Only handle errors that are not intentional cancellations
			msg := "error creating workspace for bundle..."
			c.errorReporter.CaptureError(errors.Wrap(err, msg), observability.ErrorReporterOptions{ErrorDiagnosticPath: target.GetPath()})
			return nil, bundleHash, err
		} else {
			c.logger.Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
			return nil, bundleHash, nil
		}
	}

	c.logger.Info().Str("workspaceId", workspaceId).Msg("finished wrapping the bundle in a workspace")

	response, err := c.analysisOrchestrator.RunAnalysis(ctx, c.config.Organization(), workspaceId)
	if ctx.Err() != nil {
		c.logger.Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
		return nil, bundleHash, nil
	}

	return response, bundleHash, err
}
