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
package testutil

import (
	"github.com/snyk/code-client-go/config"
	"time"
)

type localConfig struct {
}

func (l localConfig) Organization() string {
	return "3964634d-2142-4ae5-ba98-c414620609b4"
}

func (l localConfig) IsFedramp() bool {
	return false
}

func (l localConfig) SnykCodeApi() string {
	return "https://deeproxy.snyk.io"
}

func (l localConfig) SnykApi() string {
	return "https://api.snyk.io"
}

func (l localConfig) SnykCodeAnalysisTimeout() time.Duration {
	return 120 * time.Second
}

// NewTestConfig is used in pact testing.
func NewTestConfig() config.Config {
	return &localConfig{}
}
