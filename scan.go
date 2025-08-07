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
	"fmt"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"time"

	"github.com/snyk/code-client-go/bundle"
	"github.com/snyk/code-client-go/config"
	codeClientHTTP "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/internal/analysis"
	testModels "github.com/snyk/code-client-go/internal/api/test/2024-12-21/models"
	"github.com/snyk/code-client-go/internal/deepcode"
	"github.com/snyk/code-client-go/observability"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
)

type codeScanner struct {
	httpClient           codeClientHTTP.HTTPClient
	bundleManager        bundle.BundleManager
	deepcodeClient       deepcode.DeepcodeClient
	analysisOrchestrator analysis.AnalysisOrchestrator
	instrumentor         observability.Instrumentor
	errorReporter        observability.ErrorReporter
	trackerFactory       scan.TrackerFactory
	logger               *zerolog.Logger
	config               config.Config
	resultTypes          testModels.Scan
}

type CodeScanner interface {
	Upload(
		ctx context.Context,
		requestId string,
		target scan.Target,
		files <-chan string,
		changedFiles map[string]bool,
	) (bundle.Bundle, error)

	UploadAndAnalyze(
		ctx context.Context,
		requestId string,
		target scan.Target,
		files <-chan string,
		changedFiles map[string]bool,
	) (*sarif.SarifResponse, string, error)

	UploadAndAnalyzeLegacy(
		ctx context.Context,
		requestId string,
		target scan.Target,
		shardKey string,
		files <-chan string,
		changedFiles map[string]bool,
		statusChannel chan<- scan.LegacyScanStatus,
	) (*sarif.SarifResponse, string, error)
}

var _ CodeScanner = (*codeScanner)(nil)

type OptionFunc func(*codeScanner)

func WithInstrumentor(instrumentor observability.Instrumentor) OptionFunc {
	return func(c *codeScanner) {
		c.instrumentor = instrumentor
	}
}

func WithFlow(flow string) OptionFunc {
	return func(c *codeScanner) {
		switch flow {
		case "ide_test":
			c.resultTypes = testModels.CodeSecurityCodeQuality
		default:
			c.resultTypes = testModels.CodeSecurity
		}
	}
}

func WithErrorReporter(errorReporter observability.ErrorReporter) OptionFunc {
	return func(c *codeScanner) {
		c.errorReporter = errorReporter
	}
}

func WithLogger(logger *zerolog.Logger) OptionFunc {
	return func(c *codeScanner) {
		c.logger = logger
	}
}

func WithTrackerFactory(trackerFactory scan.TrackerFactory) OptionFunc {
	return func(c *codeScanner) {
		c.trackerFactory = trackerFactory
	}
}

type AnalysisOption func(*analysis.AnalysisConfig)

func ReportLocalTest(projectName string, targetName string, targetReference string) AnalysisOption {
	return func(c *analysis.AnalysisConfig) {
		c.Report = true
		c.ProjectName = &projectName
		c.TargetName = &targetName
		c.TargetReference = &targetReference
	}
}

func ReportRemoteTest(projectId uuid.UUID, commitId string) AnalysisOption {
	return func(c *analysis.AnalysisConfig) {
		c.Report = true
		c.ProjectId = &projectId
		c.CommitId = &commitId
	}
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
	trackerFactory := scan.NewNoopTrackerFactory()

	scanner := &codeScanner{
		config:         config,
		httpClient:     httpClient,
		errorReporter:  errorReporter,
		logger:         &nopLogger,
		instrumentor:   instrumentor,
		trackerFactory: trackerFactory,
		resultTypes:    testModels.CodeSecurityCodeQuality,
	}

	for _, option := range options {
		option(scanner)
	}

	// initialize other dependencies
	deepcodeClient := deepcode.NewDeepcodeClient(scanner.config, httpClient, scanner.logger, scanner.instrumentor, scanner.errorReporter)
	bundleManager := bundle.NewBundleManager(deepcodeClient, scanner.logger, scanner.instrumentor, scanner.errorReporter, scanner.trackerFactory)
	scanner.bundleManager = bundleManager
	scanner.deepcodeClient = deepcodeClient
	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		scanner.config,
		httpClient,
		analysis.WithInstrumentor(scanner.instrumentor),
		analysis.WithErrorReporter(scanner.errorReporter),
		analysis.WithTrackerFactory(scanner.trackerFactory),
		analysis.WithLogger(scanner.logger),
		analysis.WithResultType(scanner.resultTypes),
	)
	scanner.analysisOrchestrator = analysisOrchestrator

	return scanner
}

// WithBundleManager creates a new Code Scanner from the current one and replaces the bundle manager.
// It can be used to replace the bundle manager in tests.
func (c *codeScanner) WithBundleManager(bundleManager bundle.BundleManager) *codeScanner {
	return &codeScanner{
		bundleManager:        bundleManager,
		deepcodeClient:       c.deepcodeClient,
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
		deepcodeClient:       c.deepcodeClient,
		analysisOrchestrator: analysisOrchestrator,
		errorReporter:        c.errorReporter,
		logger:               c.logger,
		config:               c.config,
	}
}

// Upload creates a bundle from changed files and uploads it, returning the uploaded Bundle.
func (c *codeScanner) Upload(
	ctx context.Context,
	requestId string,
	target scan.Target,
	files <-chan string,
	changedFiles map[string]bool,
) (bundle.Bundle, error) {
	err := c.checkCancellationOrLogError(ctx, target.GetPath(), nil, "")
	if err != nil {
		return nil, err
	}

	originalBundle, err := c.bundleManager.Create(ctx, requestId, target.GetPath(), files, changedFiles)
	err = c.checkCancellationOrLogError(ctx, target.GetPath(), err, "error creating bundle...")
	if err != nil {
		return nil, err
	}

	filesToUpload := originalBundle.GetFiles()
	uploadedBundle, err := c.bundleManager.Upload(ctx, requestId, originalBundle, filesToUpload)
	err = c.checkCancellationOrLogError(ctx, target.GetPath(), err, "error uploading bundle...")
	if err != nil {
		return uploadedBundle, err
	}

	return uploadedBundle, nil
}

// Utility function to check for cancellations before optionally logging an error (if one is provided). Cancellations
// always take precedence. Returns any error or cancellation that was handled, nil otherwise.
func (c *codeScanner) checkCancellationOrLogError(ctx context.Context, targetPath string, err error, message string) error {
	returnError := ctx.Err()
	if returnError != nil {
		c.logger.Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
	} else if err != nil {
		if message != "" {
			err = errors.Wrap(err, message)
		}
		c.errorReporter.CaptureError(err, observability.ErrorReporterOptions{ErrorDiagnosticPath: targetPath})
		returnError = err
	}
	return returnError
}

func (c *codeScanner) UploadAndAnalyze(
	ctx context.Context,
	requestId string,
	target scan.Target,
	files <-chan string,
	changedFiles map[string]bool,
) (*sarif.SarifResponse, string, error) {
	response, bundleHash, _, err := c.UploadAndAnalyzeWithOptions(ctx, requestId, target, files, changedFiles)
	return response, bundleHash, err
}

func (c *codeScanner) UploadAndAnalyzeLegacy(
	ctx context.Context,
	requestId string,
	target scan.Target,
	shardKey string,
	files <-chan string,
	changedFiles map[string]bool,
	statusChannel chan<- scan.LegacyScanStatus,
) (*sarif.SarifResponse, string, error) {
	uploadedBundle, err := c.Upload(ctx, requestId, target, files, changedFiles)
	if err != nil || uploadedBundle == nil || uploadedBundle.GetBundleHash() == "" {
		c.logger.Debug().Msg("empty bundle, no Snyk Code analysis")
		return nil, "", err
	}

	bundleHash := uploadedBundle.GetBundleHash()
	limitToFiles := uploadedBundle.GetLimitToFiles()
	severity := 0

	start := time.Now()
	for {
		response, status, err := c.analysisOrchestrator.RunLegacyTest(ctx, bundleHash, shardKey, limitToFiles, severity)

		if err != nil {
			c.logger.Error().Err(err).
				Int("fileCount", len(uploadedBundle.GetFiles())).
				Msg("error retrieving diagnostics...")

			statusChannel <- scan.LegacyScanStatus{
				Message:     fmt.Sprintf("Analysis failed: %v", err),
				ScanStopped: true,
			}

			return nil, "", err
		}

		if status.Message == analysis.StatusComplete {
			c.logger.Trace().Msg("sending diagnostics...")

			statusChannel <- scan.LegacyScanStatus{
				Message:     "Analysis complete.",
				ScanStopped: true,
			}

			return response, bundleHash, err
		} else if status.Message == analysis.StatusAnalyzing {
			c.logger.Trace().Msg("\"Analyzing\" message received, sending In-Progress message to client")
		}

		if time.Since(start) > c.config.SnykCodeAnalysisTimeout() {
			err := errors.New("analysis call timed out")
			c.logger.Error().Err(err).Msg("timeout...")

			statusChannel <- scan.LegacyScanStatus{
				Message:     "Snyk Code Analysis timed out",
				ScanStopped: true,
			}
			return nil, "", err
		}

		time.Sleep(1 * time.Second)
		statusChannel <- status
	}
}

func (c *codeScanner) UploadAndAnalyzeWithOptions(
	ctx context.Context,
	requestId string,
	target scan.Target,
	files <-chan string,
	changedFiles map[string]bool,
	options ...AnalysisOption,
) (*sarif.SarifResponse, string, *scan.ResultMetaData, error) {
	uploadedBundle, err := c.Upload(ctx, requestId, target, files, changedFiles)

	if err != nil || uploadedBundle == nil || uploadedBundle.GetBundleHash() == "" {
		c.logger.Debug().Msg("empty bundle, no Snyk Code analysis")
		return nil, "", nil, err
	}

	cfg := analysis.AnalysisConfig{}
	for _, opt := range options {
		opt(&cfg)
	}

	response, metadata, err := c.analysisOrchestrator.RunTest(ctx, c.config.Organization(), uploadedBundle, target, cfg)
	err = c.checkCancellationOrLogError(ctx, target.GetPath(), err, "error running analysis...")
	if err != nil {
		return nil, "", nil, err
	}

	return response, uploadedBundle.GetBundleHash(), metadata, err
}

func (c *codeScanner) AnalyzeRemote(ctx context.Context, options ...AnalysisOption) (*sarif.SarifResponse, *scan.ResultMetaData, error) {
	cfg := analysis.AnalysisConfig{}
	for _, opt := range options {
		opt(&cfg)
	}

	err := c.checkCancellationOrLogError(ctx, "", nil, "")
	if err != nil {
		return nil, nil, err
	}
	response, metadata, err := c.analysisOrchestrator.RunTestRemote(ctx, c.config.Organization(), cfg)

	err = c.checkCancellationOrLogError(ctx, "", err, "")
	if err != nil {
		return nil, nil, err
	}

	return response, metadata, err
}
