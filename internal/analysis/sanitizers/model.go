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

// Package sanitizers holds the custom-sanitizer discovery candidate document —
// the output of `snyk code test --discover-sanitisers`. The shape follows the
// auto-discovery PRD's Appendix A; it is the contract between the CLI and the
// suggest discovery RPC, kept independent of the analysis findings model.
package sanitizers

// Kind is the taint-target a candidate plays on a flow.
const (
	KindSanitizer = "sanitizer"
	KindSource    = "source"
	KindSink      = "sink"
)

// SanitizationType mirrors the engine's sanitizer categories (Appendix A uses
// the hyphenated form). Registration maps these onto the Rule Extensions enum
// (FLOWS_THROUGH / IF_TRUE / IF_FALSE / ANY_USAGE) downstream.
const (
	SanitizationFlowsThrough = "flows-through"
	SanitizationIfTrue       = "if-true"
	SanitizationIfFalse      = "if-false"
	SanitizationAnyUsage     = "any-usage"
)

// Location is a source position for a candidate's definition or a call site.
type Location struct {
	File   string `json:"file"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
}

// Candidate is one discovered custom-sanitizer (or source/sink) candidate,
// keyed by fully qualified name.
type Candidate struct {
	Kind string `json:"kind"`
	FQN  string `json:"fqn"`
	// SanitizationType is set for sanitizer candidates; empty for source/sink.
	SanitizationType string `json:"sanitization_type,omitempty"`
	// ApplicableRules are <language>/<RuleName> entries, e.g. "java/OpenRedirect".
	ApplicableRules []string `json:"applicable_rules,omitempty"`
	Confidence      float64  `json:"confidence,omitempty"`
	Rationale       string   `json:"rationale,omitempty"`
	// Scope is the import availability: "public_library" or "internal".
	Scope      string     `json:"scope,omitempty"`
	Definition *Location  `json:"definition,omitempty"`
	CallSites  []Location `json:"call_sites,omitempty"`
}

// Document is the discovery candidate output for a scan (Appendix A shape).
type Document struct {
	ScanID     string      `json:"scan_id,omitempty"`
	Candidates []Candidate `json:"candidates"`
}
