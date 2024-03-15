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

	"github.com/rs/zerolog/log"

	"github.com/snyk/code-client-go/deepcode"
	"github.com/snyk/code-client-go/observability"
)

//go:generate mockgen -destination=mocks/bundle.go -source=bundle.go -package mocks
type Bundle interface {
	UploadBatch(ctx context.Context, host string, batch *Batch) error
	GetBundleHash() string
	GetRootPath() string
	GetRequestId() string
	GetFiles() map[string]deepcode.BundleFile
	GetMissingFiles() []string
}

type bundle struct {
	SnykCode      deepcode.SnykCodeClient
	instrumentor  observability.Instrumentor
	errorReporter observability.ErrorReporter
	requestId     string
	rootPath      string
	files         map[string]deepcode.BundleFile
	bundleHash    string
	batches       []*Batch
	missingFiles  []string
	limitToFiles  []string
}

func NewBundle(snykCode deepcode.SnykCodeClient, instrumentor observability.Instrumentor, errorReporter observability.ErrorReporter, bundleHash string, requestId string, rootPath string, files map[string]deepcode.BundleFile, limitToFiles []string, missingFiles []string) *bundle {
	return &bundle{
		SnykCode:      snykCode,
		instrumentor:  instrumentor,
		errorReporter: errorReporter,
		bundleHash:    bundleHash,
		requestId:     requestId,
		rootPath:      rootPath,
		batches:       []*Batch{},
		files:         files,
		limitToFiles:  limitToFiles,
		missingFiles:  missingFiles,
	}
}

func (b *bundle) GetBundleHash() string {
	return b.bundleHash
}

func (b *bundle) GetRootPath() string {
	return b.rootPath
}

func (b *bundle) GetRequestId() string {
	return b.requestId
}

func (b *bundle) GetFiles() map[string]deepcode.BundleFile {
	return b.files
}

func (b *bundle) GetMissingFiles() []string {
	return b.missingFiles
}

func (b *bundle) UploadBatch(ctx context.Context, host string, batch *Batch) error {
	err := b.extendBundle(ctx, host, batch)
	if err != nil {
		return err
	}
	b.batches = append(b.batches, batch)
	return nil
}

func (b *bundle) extendBundle(ctx context.Context, host string, uploadBatch *Batch) error {
	var err error
	if uploadBatch.hasContent() {
		b.bundleHash, b.missingFiles, err = b.SnykCode.ExtendBundle(ctx, host, b.bundleHash, uploadBatch.documents, []string{})
		log.Debug().Str("requestId", b.requestId).Interface("MissingFiles", b.missingFiles).Msg("extended bundle on backend")
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
func (b *Batch) canFitFile(uri string, content []byte) bool {
	docPayloadSize := b.getTotalDocPayloadSize(uri, content)
	newSize := docPayloadSize + b.getSize()
	b.size += docPayloadSize
	return newSize < maxUploadBatchSize
}

func (b *Batch) getTotalDocPayloadSize(documentURI string, content []byte) int {
	return len(jsonHashSizePerFile) + len(jsonOverheadPerFile) + len([]byte(documentURI)) + len(content)
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
