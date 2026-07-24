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

type uploadRevisionSuite struct {
	suite.Suite
	deepcodeClient *deepcodeMocks.MockDeepcodeClient
	uploader       uploadrevision.UploadRevision
	uploaded       map[string]string
	uploadCall     map[string]int
	revID          uuid.UUID
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

	logger := zerolog.Nop()
	s.uploader = uploadrevision.NewUploadRevision(
		&http.Client{Transport: transport},
		fileupload.Config{BaseURL: "https://example.com", OrgID: uuid.New()},
		s.deepcodeClient,
		&logger,
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
