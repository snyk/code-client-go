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

	"github.com/rs/zerolog"

	"github.com/snyk/code-client-go/internal/deepcode"
	"github.com/snyk/code-client-go/observability"
)

//go:generate mockgen -destination=mocks/bundle.go -source=bundle.go -package mocks
type Bundle interface {
	UploadBatch(ctx context.Context, requestId string, batch *Batch) error
	GetBundleHash() string
	GetFiles() map[string]deepcode.BundleFile
	ClearFiles()
	GetMissingFiles() []string
	GetLimitToFiles() []string
	GetRootPath() string
}

type deepCodeBundle struct {
	SnykCode      deepcode.DeepcodeClient
	instrumentor  observability.Instrumentor
	errorReporter observability.ErrorReporter
	logger        *zerolog.Logger
	files         map[string]deepcode.BundleFile
	rootPath      string
	bundleHash    string
	batches       []*Batch
	missingFiles  []string
	limitToFiles  []string
}

func NewBundle(
	snykCode deepcode.DeepcodeClient,
	instrumentor observability.Instrumentor,
	errorReporter observability.ErrorReporter,
	logger *zerolog.Logger,
	rootPath string,
	bundleHash string,
	files map[string]deepcode.BundleFile,
	limitToFiles []string,
	missingFiles []string,
) *deepCodeBundle {
	return &deepCodeBundle{
		SnykCode:      snykCode,
		instrumentor:  instrumentor,
		errorReporter: errorReporter,
		logger:        logger,
		rootPath:      rootPath,
		bundleHash:    bundleHash,
		batches:       []*Batch{},
		files:         files,
		limitToFiles:  limitToFiles,
		missingFiles:  missingFiles,
	}
}

func (b *deepCodeBundle) GetBundleHash() string {
	return b.bundleHash
}

func (b *deepCodeBundle) GetFiles() map[string]deepcode.BundleFile {
	return b.files
}

func (b *deepCodeBundle) ClearFiles() {
	b.files = map[string]deepcode.BundleFile{}
}

func (b *deepCodeBundle) GetMissingFiles() []string {
	return b.missingFiles
}

func (b *deepCodeBundle) GetLimitToFiles() []string {
	return b.limitToFiles
}

func (b *deepCodeBundle) GetRootPath() string {
	return b.rootPath
}

func (b *deepCodeBundle) UploadBatch(ctx context.Context, requestId string, batch *Batch) error {
	err := b.extendBundle(ctx, requestId, batch)
	if err != nil {
		return err
	}
	b.batches = append(b.batches, batch)
	return nil
}

func (b *deepCodeBundle) extendBundle(ctx context.Context, requestId string, uploadBatch *Batch) error {
	var err error
	if uploadBatch.hasContent() {
		b.bundleHash, b.missingFiles, err = b.SnykCode.ExtendBundle(ctx, b.bundleHash, uploadBatch.documents, []string{})
		b.logger.Debug().Str("requestId", requestId).Interface("MissingFiles", b.missingFiles).Msg("extended deepCodeBundle on backend")
	}

	return err
}

const (
	maxFileSize               = 1024 * 1024
	maxUploadBatchSize        = 1024*1024*4 - 1024 // subtract 1k for potential headers
	jsonOverheadRequest       = "{\"files\":{}}"
	jsonOverHeadRequestLength = len(jsonOverheadRequest)
	jsonUriOverhead           = "\"\":{}"
	jsonHashSizePerFile       = "\"hash\":\"0123456789012345678901234567890123456789012345678901234567890123\""
	jsonContentOverhead       = ",\"content\":\"\""
	jsonOverheadPerFile       = jsonUriOverhead + jsonContentOverhead
)

type Batch struct {
	documents map[string]deepcode.BundleFile
	size      int
}

func NewBatch(documents map[string]deepcode.BundleFile) *Batch {
	return &Batch{
		documents: documents,
	}
}

// todo simplify the size computation
// maybe consider an addFile / canFitFile interface with proper error handling
func (b *Batch) canFitFile(uri string, contentSize int) bool {
	docPayloadSize := b.getTotalDocPayloadSize(uri, contentSize)
	newSize := docPayloadSize + b.getSize()
	b.size += docPayloadSize
	return newSize < maxUploadBatchSize
}

func (b *Batch) getTotalDocPayloadSize(documentURI string, contentSize int) int {
	return len(jsonHashSizePerFile) + len(jsonOverheadPerFile) + len([]byte(documentURI)) + contentSize
}

func (b *Batch) getSize() int {
	if len(b.documents) == 0 {
		return 0
	}
	jsonCommasForFiles := len(b.documents) - 1
	var size = jsonOverHeadRequestLength + jsonCommasForFiles // if more than one file, they are separated by commas in the req
	return size + b.size
}

func (b *Batch) hasContent() bool {
	return len(b.documents) > 0
}
