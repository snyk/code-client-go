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

package sanitizers

import (
	"fmt"
	"strings"
)

// RenderHuman returns a terminal-friendly listing of the candidates. Per
// ADR-002, `--discover-sanitisers` shows candidates only (not vuln findings),
// so this is the whole human output for the flag.
func (d Document) RenderHuman() string {
	if len(d.Candidates) == 0 {
		return "No custom-sanitizer candidates found."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Discovered %d custom-sanitizer candidate(s):\n", len(d.Candidates))
	for _, c := range d.Candidates {
		fmt.Fprintf(&b, "\n  %s\n", c.FQN)
		meta := []string{"kind: " + c.Kind}
		if c.SanitizationType != "" {
			meta = append(meta, "type: "+c.SanitizationType)
		}
		if c.Confidence > 0 {
			meta = append(meta, fmt.Sprintf("confidence: %.0f%%", c.Confidence*100))
		}
		if c.Scope != "" {
			meta = append(meta, "scope: "+c.Scope)
		}
		fmt.Fprintf(&b, "    %s\n", strings.Join(meta, " · "))
		if len(c.ApplicableRules) > 0 {
			fmt.Fprintf(&b, "    rules: %s\n", strings.Join(c.ApplicableRules, ", "))
		}
		if c.Rationale != "" {
			fmt.Fprintf(&b, "    rationale: %s\n", c.Rationale)
		}
		if loc := c.Definition; loc != nil && loc.File != "" {
			fmt.Fprintf(&b, "    at %s\n", formatLocation(*loc))
		}
	}
	return b.String()
}

func formatLocation(l Location) string {
	if l.Line > 0 {
		return fmt.Sprintf("%s:%d", l.File, l.Line)
	}
	return l.File
}
