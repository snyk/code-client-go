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
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/puzpuzpuz/xsync"
	"github.com/rs/zerolog"

	"github.com/snyk/code-client-go/internal/deepcode"
	"github.com/snyk/code-client-go/internal/util"
	"github.com/snyk/code-client-go/observability"
	"github.com/snyk/code-client-go/scan"
)

//go:generate go tool github.com/golang/mock/mockgen -destination=mocks/bundle_manager.go -source=bundle_manager.go -package mocks

type bundleManager struct {
	deepcodeClient       deepcode.DeepcodeClient
	instrumentor         observability.Instrumentor
	errorReporter        observability.ErrorReporter
	logger               *zerolog.Logger
	trackerFactory       scan.TrackerFactory
	supportedExtensions  *xsync.MapOf[string, bool]
	supportedConfigFiles *xsync.MapOf[string, bool]
	filtersMu            sync.Mutex
}

// createWorkerCount returns the number of goroutines used to process files when
// creating a bundle. The work is dominated by per-file I/O (stat + read) and
// hashing, which are independent across files, so we oversubscribe the CPUs to
// keep the disk busy while syscalls block — this matters most on Windows, where
// per-file syscalls are comparatively expensive.
func createWorkerCount() int {
	n := runtime.GOMAXPROCS(0) * 4
	if n < 4 {
		n = 4
	}
	if n > 32 {
		n = 32
	}
	return n
}

type BundleManager interface {
	Create(ctx context.Context,
		requestId string,
		rootPath string,
		filePaths <-chan string,
		changedFiles map[string]bool,
	) (bundle Bundle, err error)

	// CreateEmpty does not include the file contents in the bundle.
	CreateEmpty(ctx context.Context,
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

func (b *bundleManager) Create(
	ctx context.Context,
	requestId string,
	rootPath string,
	filePaths <-chan string,
	changedFiles map[string]bool,
) (bundle Bundle, err error) {
	return b.create(ctx, rootPath, filePaths, changedFiles, true)
}

func (b *bundleManager) CreateEmpty(
	ctx context.Context,
	rootPath string,
	filePaths <-chan string,
	changedFiles map[string]bool,
) (bundle Bundle, err error) {
	return b.create(ctx, rootPath, filePaths, changedFiles, false)
}

func (b *bundleManager) create(
	ctx context.Context,
	rootPath string,
	filePaths <-chan string,
	changedFiles map[string]bool,
	includeFileContents bool,
) (bundle Bundle, err error) {
	span := b.instrumentor.StartSpan(ctx, "code.createBundle")
	defer b.instrumentor.Finish(span)

	tracker := b.trackerFactory.GenerateTracker()
	tracker.Begin("Creating file bundle", "Checking and adding files for analysis")
	defer tracker.End("")

	var limitToFiles []string
	fileHashes := make(map[string]string)
	bundleFiles := make(map[string]deepcode.BundleFile)

	// Files are processed by a pool of workers because the per-file work (stat,
	// read, hash) is I/O-bound and independent across files. Results are merged
	// under a mutex; the merge is cheap relative to the I/O, so contention is
	// negligible. The first hard error (e.g. fetching filters) aborts the run.
	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu       sync.Mutex
		firstErr error
		sawFile  atomic.Bool
		wg       sync.WaitGroup
	)
	setErr := func(e error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = e
		}
		mu.Unlock()
		cancel()
	}

	for i := 0; i < createWorkerCount(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for absoluteFilePath := range filePaths {
				sawFile.Store(true)
				if processCtx.Err() != nil {
					return
				}

				supported, supErr := b.IsSupported(processCtx, absoluteFilePath)
				if supErr != nil {
					setErr(supErr)
					return
				}
				if !supported {
					continue
				}

				bundleFile, relativePath, ok := b.bundleFileFromPath(rootPath, absoluteFilePath, includeFileContents)
				if !ok {
					continue
				}

				mu.Lock()
				bundleFiles[relativePath] = bundleFile
				fileHashes[relativePath] = bundleFile.Hash
				if changedFiles[absoluteFilePath] {
					limitToFiles = append(limitToFiles, relativePath)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Preserve the original behavior: a canceled context returns without an
	// error so the caller can decide how to handle the cancellation.
	if ctx.Err() != nil {
		return bundle, nil
	}
	if firstErr != nil {
		return bundle, firstErr
	}
	if !sawFile.Load() {
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

// bundleFileFromPath reads a single file and builds its BundleFile and encoded
// relative path. It returns ok=false for files that should be skipped (unreadable,
// empty, or larger than maxFileSize). The file is opened once and stat'd via the
// open handle to avoid a second filesystem lookup, which is noticeably cheaper on
// Windows than separate os.Stat + os.ReadFile calls.
func (b *bundleManager) bundleFileFromPath(rootPath, absoluteFilePath string, includeFileContents bool) (deepcode.BundleFile, string, bool) {
	f, openErr := os.Open(absoluteFilePath)
	if openErr != nil {
		b.logger.Error().Err(openErr).Str("filePath", absoluteFilePath).Msg("Failed to open file")
		return deepcode.BundleFile{}, "", false
	}
	defer func() { _ = f.Close() }()

	fileInfo, statErr := f.Stat()
	if statErr != nil {
		b.logger.Error().Err(statErr).Str("filePath", absoluteFilePath).Msg("Failed to read file info")
		return deepcode.BundleFile{}, "", false
	}

	size := fileInfo.Size()
	if size == 0 || size > maxFileSize {
		return deepcode.BundleFile{}, "", false
	}

	buf := bytes.NewBuffer(make([]byte, 0, size))
	if _, readErr := buf.ReadFrom(f); readErr != nil {
		b.logger.Error().Err(readErr).Str("filePath", absoluteFilePath).Msg("Failed to load content of file")
		return deepcode.BundleFile{}, "", false
	}
	fileContent := buf.Bytes()

	relativePath, relErr := util.ToRelativeUnixPath(rootPath, absoluteFilePath)
	if relErr != nil {
		b.errorReporter.CaptureError(relErr, observability.ErrorReporterOptions{ErrorDiagnosticPath: rootPath})
	}
	relativePath = util.EncodePath(relativePath)

	bundleFile, bundleErr := deepcode.BundleFileFrom(fileContent, includeFileContents)
	if bundleErr != nil {
		b.logger.Error().Err(bundleErr).Str("filePath", absoluteFilePath).Msg("Error creating bundle file")
	}
	b.logger.Trace().Str("method", "BundleFileFrom").Str("hash", bundleFile.Hash).Str("filePath", absoluteFilePath).Msg("")

	return bundleFile, relativePath, true
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
	// Guard the lazy filter load so concurrent callers (the file worker pool)
	// fetch filters exactly once. The lock is only contended on the first calls;
	// once the maps are populated the fast path below skips it entirely.
	if b.supportedExtensions.Size() == 0 && b.supportedConfigFiles.Size() == 0 {
		if err := b.loadFilters(ctx); err != nil {
			return false, err
		}
	}

	fileExtension := filepath.Ext(file)
	fileName := filepath.Base(file) // Config files are compared to the file name, not just the extensions
	_, isSupportedExtension := b.supportedExtensions.Load(fileExtension)
	_, isSupportedConfigFile := b.supportedConfigFiles.Load(fileName)

	return isSupportedExtension || isSupportedConfigFile, nil
}

func (b *bundleManager) loadFilters(ctx context.Context) error {
	b.filtersMu.Lock()
	defer b.filtersMu.Unlock()

	// Re-check under the lock: another goroutine may have populated the filters
	// while we were waiting, in which case there is nothing left to do.
	if b.supportedExtensions.Size() != 0 || b.supportedConfigFiles.Size() != 0 {
		return nil
	}

	filters, err := b.deepcodeClient.GetFilters(ctx)
	if err != nil {
		b.logger.Error().Err(err).Msg("could not get filters")
		return err
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
	return nil
}
