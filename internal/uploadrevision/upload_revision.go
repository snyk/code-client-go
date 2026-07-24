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

package uploadrevision

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"

	"github.com/snyk/code-client-go/bundle"
	"github.com/snyk/code-client-go/internal/deepcode"
	"github.com/snyk/code-client-go/internal/util"
	"github.com/snyk/code-client-go/internal/util/supportedfiles"
	"github.com/snyk/code-client-go/scan"
)

//go:generate go tool github.com/golang/mock/mockgen -destination=mocks/upload_revision.go -source=upload_revision.go -package mocks

type RevisionID string

type UploadRevision interface {
	Upload(ctx context.Context, requestId string, target scan.Target, files <-chan string) (RevisionID, error)
}

type uploadRevision struct {
	client               fileupload.Client
	supportedFilesFilter *supportedfiles.SupportedFilesFilter
	logger               *zerolog.Logger
}

var _ UploadRevision = (*uploadRevision)(nil)

func NewUploadRevision(httpClient *http.Client, cfg fileupload.Config, deepcodeClient deepcode.DeepcodeClient, logger *zerolog.Logger) *uploadRevision {
	client := fileupload.NewClient(
		httpClient,
		cfg,
		fileupload.WithPathEncoder(util.EncodePath),
		fileupload.WithContentTranscoder(newUTF8File),
	)
	return &uploadRevision{
		client:               client,
		supportedFilesFilter: supportedfiles.NewSupportedFilesFilter(deepcodeClient, logger),
		logger:               logger,
	}
}

// utf8File holds a file's content converted to UTF-8, so that the size it reports is the size
// of the content that gets streamed rather than the size of the content on disk. The upload
// client closes the file this content was read from.
type utf8File struct {
	info   fs.FileInfo
	reader *bytes.Reader
}

var _ fs.File = (*utf8File)(nil)

func newUTF8File(f fs.File) (fs.File, error) {
	content, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	// Falls back to the raw content like util.Hash does, so that a file which cannot be
	// converted is still uploaded.
	utf8Content, err := util.ConvertToUTF8(content)
	if err != nil {
		utf8Content = content
	}

	return &utf8File{info: info, reader: bytes.NewReader(utf8Content)}, nil
}

func (u *utf8File) Read(p []byte) (int, error) {
	return u.reader.Read(p)
}

func (u *utf8File) Close() error {
	return nil
}

func (u *utf8File) Stat() (fs.FileInfo, error) {
	return utf8FileInfo{FileInfo: u.info, size: u.reader.Size()}, nil
}

type utf8FileInfo struct {
	fs.FileInfo
	size int64
}

func (i utf8FileInfo) Size() int64 {
	return i.size
}

func (u *uploadRevision) Upload(ctx context.Context, requestId string, target scan.Target, files <-chan string) (RevisionID, error) {
	var supported []string
	noFiles := true
	for path := range files {
		noFiles = false
		isSupported, err := u.supportedFilesFilter.IsFileSupported(ctx, path)
		if err != nil {
			return "", err
		}
		if isSupported {
			supported = append(supported, path)
		}
	}

	if noFiles {
		return "", bundle.NoFilesError{}
	}

	supportedFiles := make(chan string, len(supported))
	for _, path := range supported {
		supportedFiles <- path
	}
	close(supportedFiles)

	res, err := u.client.CreateRevisionFromChan(ctx, supportedFiles, target.GetPath())
	if err != nil {
		if errors.Is(err, fileupload.ErrNoFilesProvided) {
			return "", bundle.NoFilesError{}
		}
		return "", err
	}

	return RevisionID(res.RevisionID.String()), nil
}
