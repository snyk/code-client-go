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

package uploadrevision_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/stretchr/testify/suite"

	"github.com/snyk/code-client-go/bundle"
	"github.com/snyk/code-client-go/internal/deepcode"
	deepcodeMocks "github.com/snyk/code-client-go/internal/deepcode/mocks"
	"github.com/snyk/code-client-go/internal/uploadrevision"
	"github.com/snyk/code-client-go/scan"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

// recordingTracker captures the progress calls the upload makes.
type recordingTracker struct {
	begun []string
	ended []string
}

func (t *recordingTracker) Begin(title, message string) {
	t.begun = append(t.begun, title+" - "+message)
}

func (t *recordingTracker) End(message string) {
	t.ended = append(t.ended, message)
}

func (t *recordingTracker) GenerateTracker() scan.Tracker {
	return t
}

type uploadRevisionSuite struct {
	suite.Suite
	deepcodeClient  *deepcodeMocks.MockDeepcodeClient
	uploader        uploadrevision.UploadRevision
	uploaded        map[string]string
	uploadCall      map[string]int
	revID           uuid.UUID
	analyticsClient analytics.Analytics
	tracker         *recordingTracker
	logs            *bytes.Buffer
}

// recordedExtensions returns the analytics extension values the upload recorded. Integers come
// back as float64 because the collector round-trips the extension map through JSON.
func (s *uploadRevisionSuite) recordedExtensions() map[string]interface{} {
	body, err := analytics.GetV2InstrumentationObject(s.analyticsClient.GetInstrumentation())
	s.Require().NoError(err)

	if body.Data.Attributes.Interaction.Extension == nil {
		return map[string]interface{}{}
	}
	return *body.Data.Attributes.Interaction.Extension
}

func TestUploadRevisionSuite(t *testing.T) {
	suite.Run(t, new(uploadRevisionSuite))
}

func (s *uploadRevisionSuite) SetupTest() {
	ctrl := gomock.NewController(s.T())
	s.deepcodeClient = deepcodeMocks.NewMockDeepcodeClient(ctrl)
	s.uploaded = map[string]string{}
	s.uploadCall = map[string]int{}
	s.revID = uuid.New()
	populateCall := 0

	createResp := fmt.Sprintf(`{"data":{"id":%q,"type":"upload_revision","attributes":{"revision_type":"snapshot","sealed":false}}}`, s.revID)
	sealResp := fmt.Sprintf(`{"data":{"id":%q,"type":"upload_revision","attributes":{"revision_type":"snapshot","sealed":true}}}`, s.revID)

	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/files"):
			populateCall++
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				return nil, err
			}
			_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil {
				return nil, err
			}
			mr := multipart.NewReader(gz, params["boundary"])
			for {
				part, err := mr.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					return nil, err
				}
				content, _ := io.ReadAll(part)
				s.uploaded[part.FormName()] = string(content)
				s.uploadCall[part.FormName()] = populateCall
			}
			return response(http.StatusNoContent, ""), nil
		case r.Method == http.MethodPost:
			return response(http.StatusCreated, createResp), nil
		case r.Method == http.MethodPatch:
			return response(http.StatusOK, sealResp), nil
		default:
			return nil, fmt.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	s.logs = &bytes.Buffer{}
	logger := zerolog.New(s.logs)
	s.analyticsClient = analytics.New()
	s.tracker = &recordingTracker{}
	s.uploader = uploadrevision.NewUploadRevision(
		&http.Client{Transport: transport},
		fileupload.Config{BaseURL: "https://example.com", OrgID: uuid.New()},
		s.deepcodeClient,
		&logger,
		s.analyticsClient,
		s.tracker,
	)
}

func (s *uploadRevisionSuite) TestUpload_NoFiles() {
	files := make(chan string)
	close(files)

	revisionID, err := s.uploader.Upload(context.Background(), "requestId", scan.RepositoryTarget{LocalFilePath: "/path"}, files)

	s.Empty(revisionID)
	s.True(bundle.IsNoFilesError(err))
	s.Empty(s.uploaded)
}

func (s *uploadRevisionSuite) TestUpload_StopsOnCancelledContext() {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	files := make(chan string, 3)
	files <- "/path/a.go"
	files <- "/path/b.go"
	files <- "/path/c.go"
	close(files)

	_, err := s.uploader.Upload(ctx, "requestId", scan.RepositoryTarget{LocalFilePath: "/path"}, files)

	s.Require().ErrorIs(err, context.Canceled)
	// The remaining paths are left unread rather than the whole channel being drained. No
	// GetFilters call is set up either, so filtering must not have started.
	s.Len(files, 2)
}

func (s *uploadRevisionSuite) TestUpload_SingleFileExcludedByFilters() {
	s.deepcodeClient.EXPECT().GetFilters(gomock.Any()).Return(deepcode.FiltersResponse{
		ConfigFiles: []string{},
		Extensions:  []string{".java"},
	}, nil)

	files := make(chan string, 1)
	files <- "/path/file.txt"
	close(files)

	revisionID, err := s.uploader.Upload(context.Background(), "requestId", scan.RepositoryTarget{LocalFilePath: "/path"}, files)

	s.True(bundle.IsNoFilesError(err))
	s.Empty(revisionID)
	s.Empty(s.uploaded)
}

func (s *uploadRevisionSuite) TestUpload_SingleFile() {
	s.deepcodeClient.EXPECT().GetFilters(gomock.Any()).Return(deepcode.FiltersResponse{
		ConfigFiles: []string{},
		Extensions:  []string{".go"},
	}, nil)

	dir := s.T().TempDir()
	s.writeFile(dir, "main.go", []byte("package main"))

	files := make(chan string, 1)
	files <- filepath.Join(dir, "main.go")
	close(files)

	revisionID, err := s.uploader.Upload(context.Background(), "requestId", scan.RepositoryTarget{LocalFilePath: dir}, files)

	s.Require().NoError(err)
	s.Equal(uploadrevision.RevisionID(s.revID.String()), revisionID)
	s.Require().Len(s.uploaded, 1)
	s.Equal("package main", s.uploaded["main.go"])
	s.Equal(1, s.uploadCall["main.go"])
}

func (s *uploadRevisionSuite) TestUpload_RecordsFileCountsBeforeAndAfterFiltering() {
	s.deepcodeClient.EXPECT().GetFilters(gomock.Any()).Return(deepcode.FiltersResponse{
		ConfigFiles: []string{},
		Extensions:  []string{".go"},
	}, nil)

	dir := s.T().TempDir()
	s.writeFile(dir, "main.go", []byte("package main"))
	s.writeFile(dir, "notes.txt", []byte("not supported"))

	files := make(chan string, 2)
	files <- filepath.Join(dir, "main.go")
	files <- filepath.Join(dir, "notes.txt")
	close(files)

	_, err := s.uploader.Upload(context.Background(), "requestId", scan.RepositoryTarget{LocalFilePath: dir}, files)
	s.Require().NoError(err)

	extensions := s.recordedExtensions()
	s.Equal(float64(2), extensions["files_to_upload_before_filtering"])
	s.Equal(float64(1), extensions["files_to_upload_after_filtering"])
}

func (s *uploadRevisionSuite) TestUpload_LogsUploadClientOutput() {
	s.deepcodeClient.EXPECT().GetFilters(gomock.Any()).Return(deepcode.FiltersResponse{
		ConfigFiles: []string{},
		Extensions:  []string{".go"},
	}, nil)

	dir := s.T().TempDir()
	s.writeFile(dir, "main.go", []byte("package main"))

	files := make(chan string, 1)
	files <- filepath.Join(dir, "main.go")
	close(files)

	_, err := s.uploader.Upload(context.Background(), "requestId", scan.RepositoryTarget{LocalFilePath: dir}, files)
	s.Require().NoError(err)

	// This field is logged by the upload client itself, so its presence proves the client was
	// given a real logger rather than the no-op one it defaults to.
	s.Contains(s.logs.String(), "file_size_limit_bytes")
}

func (s *uploadRevisionSuite) TestUpload_ReportsProgress() {
	s.deepcodeClient.EXPECT().GetFilters(gomock.Any()).Return(deepcode.FiltersResponse{
		ConfigFiles: []string{},
		Extensions:  []string{".go"},
	}, nil)

	dir := s.T().TempDir()
	s.writeFile(dir, "main.go", []byte("package main"))

	files := make(chan string, 1)
	files <- filepath.Join(dir, "main.go")
	close(files)

	_, err := s.uploader.Upload(context.Background(), "requestId", scan.RepositoryTarget{LocalFilePath: dir}, files)
	s.Require().NoError(err)

	s.Equal([]string{
		"Snyk Code analysis for " + dir + " - Checking files for analysis",
		"Snyk Code analysis for " + dir + " - Uploading files...",
	}, s.tracker.begun)
	s.Equal([]string{""}, s.tracker.ended)
}

func (s *uploadRevisionSuite) TestUpload_EndsProgressWhenNoFilesAreSupported() {
	s.deepcodeClient.EXPECT().GetFilters(gomock.Any()).Return(deepcode.FiltersResponse{
		ConfigFiles: []string{},
		Extensions:  []string{".java"},
	}, nil)

	files := make(chan string, 1)
	files <- "/path/file.txt"
	close(files)

	_, err := s.uploader.Upload(context.Background(), "requestId", scan.RepositoryTarget{LocalFilePath: "/path"}, files)
	s.Require().Error(err)

	s.Equal([]string{""}, s.tracker.ended)
}

func (s *uploadRevisionSuite) TestUpload_RecordsFilesExcludedDuringUpload() {
	s.deepcodeClient.EXPECT().GetFilters(gomock.Any()).Return(deepcode.FiltersResponse{
		ConfigFiles: []string{},
		Extensions:  []string{".go"},
	}, nil)

	dir := s.T().TempDir()
	s.writeFile(dir, "main.go", []byte("package main"))
	// A path over the client's 256 character limit is the simplest exclusion to trigger here.
	excludedRelPath := filepath.Join(strings.Repeat("a", 250), "excluded.go")
	s.writeFile(dir, excludedRelPath, []byte("package excluded"))

	files := make(chan string, 2)
	files <- filepath.Join(dir, "main.go")
	files <- filepath.Join(dir, excludedRelPath)
	close(files)

	_, err := s.uploader.Upload(context.Background(), "requestId", scan.RepositoryTarget{LocalFilePath: dir}, files)
	s.Require().NoError(err)

	s.Equal(float64(1), s.recordedExtensions()["files_excluded_during_upload"])
	s.Equal("package main", s.uploaded["main.go"])
}

func (s *uploadRevisionSuite) TestUpload_EncodesPaths() {
	s.deepcodeClient.EXPECT().GetFilters(gomock.Any()).Return(deepcode.FiltersResponse{
		ConfigFiles: []string{},
		Extensions:  []string{".go"},
	}, nil)

	dir := s.T().TempDir()
	s.writeFile(dir, filepath.Join("sub dir", "a b.go"), []byte("package a"))

	files := make(chan string, 1)
	files <- filepath.Join(dir, "sub dir", "a b.go")
	close(files)

	_, err := s.uploader.Upload(context.Background(), "requestId", scan.RepositoryTarget{LocalFilePath: dir}, files)

	s.Require().NoError(err)
	s.Require().Len(s.uploaded, 1)
	s.Equal("package a", s.uploaded["sub%20dir/a%20b.go"])
}

func (s *uploadRevisionSuite) TestUpload_TranscodesContent() {
	s.deepcodeClient.EXPECT().GetFilters(gomock.Any()).Return(deepcode.FiltersResponse{
		ConfigFiles: []string{},
		Extensions:  []string{".go"},
	}, nil)

	dir := s.T().TempDir()
	s.writeFile(dir, "main.go", append([]byte("package main"), 0xff))

	files := make(chan string, 1)
	files <- filepath.Join(dir, "main.go")
	close(files)

	_, err := s.uploader.Upload(context.Background(), "requestId", scan.RepositoryTarget{LocalFilePath: dir}, files)

	s.Require().NoError(err)
	s.Require().Len(s.uploaded, 1)
	s.Equal("package main�", s.uploaded["main.go"])
}

func (s *uploadRevisionSuite) writeFile(dir, relPath string, content []byte) {
	fullPath := filepath.Join(dir, relPath)
	s.Require().NoError(os.MkdirAll(filepath.Dir(fullPath), 0o755))
	s.Require().NoError(os.WriteFile(fullPath, content, 0o600))
}
