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

package bundle

import (
	"context"
	"github.com/snyk/code-client-go/scan"
	"os"
	"path/filepath"

	"github.com/puzpuzpuz/xsync"
	"github.com/rs/zerolog"

	"github.com/snyk/code-client-go/internal/deepcode"
	"github.com/snyk/code-client-go/internal/util"
	"github.com/snyk/code-client-go/observability"
)

type bundleManager struct {
	deepcodeClient       deepcode.DeepcodeClient
	instrumentor         observability.Instrumentor
	errorReporter        observability.ErrorReporter
	logger               *zerolog.Logger
	trackerFactory       scan.TrackerFactory
	supportedExtensions  *xsync.MapOf[string, bool]
	supportedConfigFiles *xsync.MapOf[string, bool]
}

//go:generate mockgen -destination=mocks/bundle_manager.go -source=bundle_manager.go -package mocks
type BundleManager interface {
	Create(ctx context.Context,
		requestId string,
		rootPath string,
		filePaths <-chan string,
		changedFiles map[string]bool,
	) (bundle Bundle, err error)

	Upload(
		ctx context.Context,
		requestId string,
		originalBundle Bundle,
		files map[string]deepcode.BundleFile,
	) (Bundle, error)
}

func NewBundleManager(
	deepcodeClient deepcode.DeepcodeClient,
	logger *zerolog.Logger,
	instrumentor observability.Instrumentor,
	errorReporter observability.ErrorReporter,
	trackerFactory scan.TrackerFactory,
) *bundleManager {
	return &bundleManager{
		deepcodeClient:       deepcodeClient,
		instrumentor:         instrumentor,
		errorReporter:        errorReporter,
		logger:               logger,
		trackerFactory:       trackerFactory,
		supportedExtensions:  xsync.NewMapOf[bool](),
		supportedConfigFiles: xsync.NewMapOf[bool](),
	}
}

func (b *bundleManager) Create(ctx context.Context,
	requestId string,
	rootPath string,
	filePaths <-chan string,
	changedFiles map[string]bool,
) (bundle Bundle, err error) {
	span := b.instrumentor.StartSpan(ctx, "code.createBundle")
	defer b.instrumentor.Finish(span)

	tracker := b.trackerFactory.GenerateTracker()
	tracker.Begin("Creating file bundle", "Checking and adding files for analysis")
	defer tracker.End("")

	var limitToFiles []string
	fileHashes := make(map[string]string)
	bundleFiles := make(map[string]deepcode.BundleFile)
	noFiles := true
	for absoluteFilePath := range filePaths {
		noFiles = false
		if ctx.Err() != nil {
			return bundle, err // The cancellation error should be handled by the calling function
		}
		var supported bool
		supported, err = b.IsSupported(span.Context(), absoluteFilePath)
		if err != nil {
			return bundle, err
		}
		if !supported {
			continue
		}

		fileInfo, fileErr := os.Stat(absoluteFilePath)
		if fileErr != nil {
			b.logger.Error().Err(err).Str("filePath", absoluteFilePath).Msg("Failed to read file info")
			continue
		}

		if fileInfo.Size() == 0 || fileInfo.Size() > maxFileSize {
			continue
		}

		fileContent, fileErr := os.ReadFile(absoluteFilePath)
		if fileErr != nil {
			b.logger.Error().Err(err).Str("filePath", absoluteFilePath).Msg("Failed to load content of file")
			continue
		}

		relativePath, fileErr := util.ToRelativeUnixPath(rootPath, absoluteFilePath)
		if fileErr != nil {
			b.errorReporter.CaptureError(err, observability.ErrorReporterOptions{ErrorDiagnosticPath: rootPath})
		}
		relativePath = util.EncodePath(relativePath)

		bundleFile := deepcode.BundleFileFrom(fileContent)
		bundleFiles[relativePath] = bundleFile
		fileHashes[relativePath] = bundleFile.Hash
		b.logger.Trace().Str("method", "BundleFileFrom").Str("hash", bundleFile.Hash).Str("filePath", absoluteFilePath).Msg("")

		if changedFiles[absoluteFilePath] {
			limitToFiles = append(limitToFiles, relativePath)
		}
	}

	if noFiles {
		return bundle, NoFilesError{}
	}

	var bundleHash string
	var missingFiles []string
	if len(fileHashes) > 0 {
		bundleHash, missingFiles, err = b.deepcodeClient.CreateBundle(span.Context(), fileHashes)
	}
	bundle = NewBundle(
		b.deepcodeClient,
		b.instrumentor,
		b.errorReporter,
		b.logger,
		rootPath,
		bundleHash,
		bundleFiles,
		limitToFiles,
		missingFiles,
	)
	return bundle, err
}

func (b *bundleManager) Upload(
	ctx context.Context,
	requestId string,
	bundle Bundle,
	files map[string]deepcode.BundleFile,
) (Bundle, error) {
	method := "code.Batch"
	s := b.instrumentor.StartSpan(ctx, method)
	defer b.instrumentor.Finish(s)

	tracker := b.trackerFactory.GenerateTracker()
	tracker.Begin("Snyk Code analysis for "+bundle.GetRootPath(), "Uploading batches...")
	defer tracker.End("Upload done.")

	// make uploads in batches until no missing files reported anymore
	for len(bundle.GetMissingFiles()) > 0 {
		batches := b.groupInBatches(s.Context(), bundle, files)
		if len(batches) == 0 {
			return bundle, nil
		}

		for _, batch := range batches {
			if err := ctx.Err(); err != nil {
				return bundle, err
			}
			b.enrichBatchWithFileContent(batch, bundle.GetRootPath())
			err := bundle.UploadBatch(s.Context(), requestId, batch)
			if err != nil {
				return bundle, err
			}
			batch.documents = make(map[string]deepcode.BundleFile)
		}
	}

	// bundle doesn't need file map anymore since they are already grouped and uploaded
	bundle.ClearFiles()
	return bundle, nil
}

func (b *bundleManager) enrichBatchWithFileContent(batch *Batch, rootPath string) {
	for filePath, bundleFile := range batch.documents {
		absPath, err := util.DecodePath(util.ToAbsolutePath(rootPath, filePath))
		if err != nil {
			b.logger.Error().Err(err).Str("file", filePath).Msg("Failed to decode Path")
			continue
		}
		content, err := os.ReadFile(absPath)
		if err != nil {
			b.logger.Error().Err(err).Str("file", filePath).Msg("Failed to read bundle file")
			continue
		}

		utf8Content, err := util.ConvertToUTF8(content)
		if err != nil {
			b.logger.Error().Err(err).Str("file", filePath).Msg("Failed to convert bundle file to UTF-8")
			continue
		}

		bundleFile.Content = string(utf8Content)
		batch.documents[filePath] = bundleFile
	}
}

func (b *bundleManager) groupInBatches(
	ctx context.Context,
	bundle Bundle,
	files map[string]deepcode.BundleFile,
) []*Batch {
	method := "code.groupInBatches"
	s := b.instrumentor.StartSpan(ctx, method)
	defer b.instrumentor.Finish(s)

	tracker := b.trackerFactory.GenerateTracker()
	tracker.Begin("Snyk Code analysis for "+bundle.GetRootPath(), "Creating batches...")
	defer tracker.End("Batches created.")

	var batches []*Batch
	batch := NewBatch(map[string]deepcode.BundleFile{})
	for _, filePath := range bundle.GetMissingFiles() {
		if len(batches) == 0 { // first batch added after first file found
			batches = append(batches, batch)
		}

		file := files[filePath]
		if batch.canFitFile(filePath, file.ContentSize) {
			b.logger.Trace().Str("path", filePath).Int("size", file.ContentSize).Msgf("added to deepCodeBundle #%v", len(batches))
			batch.documents[filePath] = file
		} else {
			b.logger.Trace().Str("path", filePath).Int("size", file.ContentSize).Msgf("created new deepCodeBundle - %v bundles in this upload so far", len(batches))
			newUploadBatch := NewBatch(map[string]deepcode.BundleFile{})
			newUploadBatch.documents[filePath] = file
			batches = append(batches, newUploadBatch)
			batch = newUploadBatch
		}
	}
	return batches
}

func (b *bundleManager) IsSupported(ctx context.Context, file string) (bool, error) {
	if b.supportedExtensions.Size() == 0 && b.supportedConfigFiles.Size() == 0 {
		filters, err := b.deepcodeClient.GetFilters(ctx)
		if err != nil {
			b.logger.Error().Err(err).Msg("could not get filters")
			return false, err
		}

		for _, ext := range filters.Extensions {
			b.supportedExtensions.Store(ext, true)
		}
		for _, configFile := range filters.ConfigFiles {
			// .gitignore and .dcignore should not be uploaded
			// (https://github.com/snyk/code-client/blob/d6f6a2ce4c14cb4b05aa03fb9f03533d8cf6ca4a/src/files.ts#L138)
			if configFile == ".gitignore" || configFile == ".dcignore" {
				continue
			}
			b.supportedConfigFiles.Store(configFile, true)
		}
	}

	fileExtension := filepath.Ext(file)
	fileName := filepath.Base(file) // Config files are compared to the file name, not just the extensions
	_, isSupportedExtension := b.supportedExtensions.Load(fileExtension)
	_, isSupportedConfigFile := b.supportedConfigFiles.Load(fileName)

	return isSupportedExtension || isSupportedConfigFile, nil
}
