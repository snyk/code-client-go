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

//nolint:lll // Some of the lines in this file are going to be long for now.
package codeclient

import (
	"github.com/snyk/code-client-go/internal/analysis"
	"github.com/snyk/code-client-go/sarif"
)

// UploadAndAnalyze returns a fake SARIF response for testing. Use target-service to run analysis on.
func UploadAndAnalyze() (*sarif.SarifResponse, error) {
	return analysis.RunAnalysis()
}
