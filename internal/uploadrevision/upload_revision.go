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
	"context"
	"errors"
	"net/http"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/analytics"
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
	analytics            analytics.Analytics
	trackerFactory       scan.TrackerFactory
}

var _ UploadRevision = (*uploadRevision)(nil)

func NewUploadRevision(httpClient *http.Client, cfg fileupload.Config, deepcodeClient deepcode.DeepcodeClient, logger *zerolog.Logger, analyticsClient analytics.Analytics, trackerFactory scan.TrackerFactory) *uploadRevision {
	client := fileupload.NewClient(
		httpClient,
		cfg,
		fileupload.WithPathEncoder(util.EncodePath),
		fileupload.WithContentTranscoder(toUTF8),
	)
	return &uploadRevision{
		client:               client,
		supportedFilesFilter: supportedfiles.NewSupportedFilesFilter(deepcodeClient, logger),
		logger:               logger,
		analytics:            analyticsClient,
		trackerFactory:       trackerFactory,
	}
}

// toUTF8 converts a file's content to UTF-8. It falls back to the raw content like util.Hash
// does, so that a file which cannot be converted is still uploaded rather than skipped.
func toUTF8(content []byte) ([]byte, error) {
	utf8Content, err := util.ConvertToUTF8(content)
	if err != nil {
		return content, nil
	}

	return utf8Content, nil
}

func (u *uploadRevision) Upload(ctx context.Context, requestId string, target scan.Target, files <-chan string) (RevisionID, error) {
	tracker := u.trackerFactory.GenerateTracker()
	tracker.Begin("Snyk Code analysis for "+target.GetPath(), "Checking files for analysis")
	defer tracker.End("")

	var supported []string
	filesBeforeFiltering := 0
	for path := range files {
		filesBeforeFiltering++
		if ctx.Err() != nil {
			return "", ctx.Err() // The cancellation error should be handled by the calling function
		}

		isSupported, err := u.supportedFilesFilter.IsFileSupported(ctx, path)
		if err != nil {
			return "", err
		}
		if isSupported {
			supported = append(supported, path)
		}
	}

	supportedfiles.RecordFileFiltering(u.analytics, u.logger, filesBeforeFiltering, len(supported))

	if filesBeforeFiltering == 0 {
		return "", bundle.NoFilesError{}
	}

	supportedFiles := make(chan string, len(supported))
	for _, path := range supported {
		supportedFiles <- path
	}
	close(supportedFiles)

	tracker.Begin("Snyk Code analysis for "+target.GetPath(), "Uploading files...")

	res, err := u.client.CreateRevisionFromChan(ctx, supportedFiles, target.GetPath())
	u.recordUploadExclusions(res.SkippedFiles)
	if err != nil {
		if errors.Is(err, fileupload.ErrNoFilesProvided) {
			return "", bundle.NoFilesError{}
		}
		return "", err
	}

	return RevisionID(res.RevisionID.String()), nil
}

// recordUploadExclusions reports the files the upload client skipped, with each file's reason so
// that a file missing from a scan can be explained.
func (u *uploadRevision) recordUploadExclusions(skippedFiles []fileupload.SkippedFile) {
	u.analytics.AddExtensionIntegerValue("files_excluded_during_upload", len(skippedFiles))

	u.logger.Info().
		Int("excludedFiles", len(skippedFiles)).
		Msg("Snyk Code upload exclusions")

	for _, skippedFile := range skippedFiles {
		u.logger.Debug().
			Err(skippedFile.Reason).
			Str("filePath", skippedFile.Path).
			Msg("File excluded from upload")
	}
}
