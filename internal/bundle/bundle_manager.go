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
	"os"
	"path/filepath"

	"github.com/puzpuzpuz/xsync"
	"github.com/rs/zerolog"

	"github.com/snyk/code-client-go/internal/deepcode"
	"github.com/snyk/code-client-go/internal/util"
	"github.com/snyk/code-client-go/observability"
)

// TODO: add progress tracker for percentage progress
type bundleManager struct {
	SnykCode             deepcode.SnykCodeClient
	instrumentor         observability.Instrumentor
	errorReporter        observability.ErrorReporter
	logger               *zerolog.Logger
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
	logger *zerolog.Logger,
	SnykCode deepcode.SnykCodeClient,
	instrumentor observability.Instrumentor,
	errorReporter observability.ErrorReporter,
) *bundleManager {
	return &bundleManager{
		SnykCode:             SnykCode,
		instrumentor:         instrumentor,
		errorReporter:        errorReporter,
		logger:               logger,
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
		var fileContent []byte
		fileContent, err = os.ReadFile(absoluteFilePath)
		if err != nil {
			b.logger.Error().Err(err).Str("filePath", absoluteFilePath).Msg("could not load content of file")
			continue
		}

		if !(len(fileContent) > 0 && len(fileContent) <= maxFileSize) {
			continue
		}

		var relativePath string
		relativePath, err = util.ToRelativeUnixPath(rootPath, absoluteFilePath)
		if err != nil {
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
		bundleHash, missingFiles, err = b.SnykCode.CreateBundle(span.Context(), fileHashes)
	}
	bundle = NewBundle(
		b.SnykCode,
		b.instrumentor,
		b.errorReporter,
		b.logger,
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
			err := bundle.UploadBatch(s.Context(), requestId, batch)
			if err != nil {
				return bundle, err
			}
		}
	}

	return bundle, nil
}

func (b *bundleManager) groupInBatches(
	ctx context.Context,
	bundle Bundle,
	files map[string]deepcode.BundleFile,
) []*Batch {
	method := "code.groupInBatches"
	s := b.instrumentor.StartSpan(ctx, method)
	defer b.instrumentor.Finish(s)

	var batches []*Batch
	batch := NewBatch(map[string]deepcode.BundleFile{})
	for _, filePath := range bundle.GetMissingFiles() {
		if len(batches) == 0 { // first batch added after first file found
			batches = append(batches, batch)
		}

		file := files[filePath]
		var fileContent = []byte(file.Content)
		if batch.canFitFile(filePath, fileContent) {
			b.logger.Trace().Str("path", filePath).Int("size", len(fileContent)).Msgf("added to deepCodeBundle #%v", len(batches))
			batch.documents[filePath] = file
		} else {
			b.logger.Trace().Str("path", filePath).Int("size", len(fileContent)).Msgf("created new deepCodeBundle - %v bundles in this upload so far", len(batches))
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
		filters, err := b.SnykCode.GetFilters(ctx)
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
