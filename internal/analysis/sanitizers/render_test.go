/*
 * © 2026 Snyk Limited All rights reserved.
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

package sanitizers_test

import (
	"testing"

	"github.com/snyk/code-client-go/internal/analysis/sanitizers"
	"github.com/stretchr/testify/assert"
)

func sampleDoc() sanitizers.Document {
	return sanitizers.Document{
		ScanID: "scan-7f2a3c",
		Candidates: []sanitizers.Candidate{
			{
				Kind:             sanitizers.KindSanitizer,
				FQN:              "io.snyk.demo.rules.UsernameValidator.isValidUsername",
				SanitizationType: sanitizers.SanitizationIfTrue,
				ApplicableRules:  []string{"javascript/OpenRedirect", "java/OpenRedirect"},
				Confidence:       0.91,
				Scope:            "internal",
				Rationale:        "Guard before tainted redirects; 14 call-sites.",
				Definition:       &sanitizers.Location{File: "src/rules/validator.java", Line: 42},
			},
		},
	}
}

func TestRenderHuman_ListsCandidateDetails(t *testing.T) {
	out := sampleDoc().RenderHuman()
	assert.Contains(t, out, "Discovered 1 custom-sanitizer candidate(s):")
	assert.Contains(t, out, "io.snyk.demo.rules.UsernameValidator.isValidUsername")
	assert.Contains(t, out, "type: if-true")
	assert.Contains(t, out, "confidence: 91%")
	assert.Contains(t, out, "scope: internal")
	assert.Contains(t, out, "rules: javascript/OpenRedirect, java/OpenRedirect")
	assert.Contains(t, out, "at src/rules/validator.java:42")
}

func TestRenderHuman_EmptyIsClear(t *testing.T) {
	assert.Equal(t, "No custom-sanitizer candidates found.", sanitizers.Document{}.RenderHuman())
}
