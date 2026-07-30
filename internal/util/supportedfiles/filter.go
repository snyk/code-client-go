/*
 * © 2022-2024 Snyk Limited All rights reserved.
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
package supportedfiles

import (
	"context"
	"os"
	"path/filepath"

	"github.com/puzpuzpuz/xsync"
	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/internal/deepcode"
)

const maxFileSize = 1024 * 1024

type SupportedFilesFilter struct {
	client               deepcode.DeepcodeClient
	logger               *zerolog.Logger
	supportedExtensions  *xsync.MapOf[string, bool]
	supportedConfigFiles *xsync.MapOf[string, bool]
}

func NewSupportedFilesFilter(client deepcode.DeepcodeClient, logger *zerolog.Logger) *SupportedFilesFilter {
	return &SupportedFilesFilter{
		client:               client,
		logger:               logger,
		supportedExtensions:  xsync.NewMapOf[bool](),
		supportedConfigFiles: xsync.NewMapOf[bool](),
	}
}

func (s *SupportedFilesFilter) isPathSupported(ctx context.Context, path string) (bool, error) {
	if s.supportedExtensions.Size() == 0 && s.supportedConfigFiles.Size() == 0 {
		filters, err := s.client.GetFilters(ctx)
		if err != nil {
			s.logger.Error().Err(err).Msg("could not get filters")
			return false, err
		}

		for _, ext := range filters.Extensions {
			s.supportedExtensions.Store(ext, true)
		}
		for _, configFile := range filters.ConfigFiles {
			// .gitignore and .dcignore should not be uploaded
			// (https://github.com/snyk/code-client/blob/d6f6a2ce4c14cb4b05aa03fb9f03533d8cf6ca4a/src/files.ts#L138)
			if configFile == ".gitignore" || configFile == ".dcignore" {
				continue
			}
			s.supportedConfigFiles.Store(configFile, true)
		}
	}

	fileExtension := filepath.Ext(path)
	fileName := filepath.Base(path) // Config files are compared to the file name, not just the extensions
	_, isSupportedExtension := s.supportedExtensions.Load(fileExtension)
	_, isSupportedConfigFile := s.supportedConfigFiles.Load(fileName)

	return isSupportedExtension || isSupportedConfigFile, nil
}

func (s *SupportedFilesFilter) IsFileSupported(ctx context.Context, path string) (bool, error) {
	supported, err := s.isPathSupported(ctx, path)
	if err != nil {
		return false, err
	}
	if !supported {
		return false, nil
	}

	fileInfo, fileErr := os.Stat(path)
	if fileErr != nil {
		s.logger.Error().Err(fileErr).Str("filePath", path).Msg("Failed to read file info")
		return false, nil
	}

	if fileInfo.Size() == 0 || fileInfo.Size() > maxFileSize {
		return false, nil
	}
	return true, nil
}
