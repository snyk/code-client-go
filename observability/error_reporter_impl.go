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

package observability

import (
	"github.com/rs/zerolog"
)

type errorReporter struct {
	logger *zerolog.Logger
}

func NewErrorReporter(logger *zerolog.Logger) ErrorReporter {
	return &errorReporter{logger}
}

func (s *errorReporter) FlushErrorReporting() {
}

func (s *errorReporter) CaptureError(err error, options ErrorReporterOptions) bool {
	s.logger.Log().Err(err).Msg("An error has been captured by the error reporter")
	return true
}
