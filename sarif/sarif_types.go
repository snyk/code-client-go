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

//nolint:revive,tagliatelle // These are all SARIF documented types that need to match the exact JSON format.
package sarif

// SarifDocument matches the spec in https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json
type SarifDocument struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type SarifCoverage struct {
	Files       int    `json:"files"`
	IsSupported bool   `json:"isSupported"`
	Lang        string `json:"lang"`
}

type SarifResponse struct {
	Type     string  `json:"type"`
	Progress float64 `json:"progress"`
	Status   string  `json:"status"`
	Timing   struct {
		FetchingCode int `json:"fetchingCode"`
		Queue        int `json:"queue"`
		Analysis     int `json:"analysis"`
	} `json:"timing"`
	Coverage []SarifCoverage `json:"coverage"`
	Sarif    SarifDocument   `json:"sarif"`
}

type Region struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine"`
	StartColumn int `json:"startColumn"`
	EndColumn   int `json:"endColumn"`
}

type ArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type Location struct {
	ID               int              `json:"id"`
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type ThreadFlowLocation struct {
	Location Location `json:"location"`
}

type ThreadFlow struct {
	Locations []ThreadFlowLocation `json:"locations"`
}

type CodeFlow struct {
	ThreadFlows []ThreadFlow `json:"threadFlows"`
}

type ResultMessage struct {
	Text      string   `json:"text"`
	Markdown  string   `json:"markdown"`
	Arguments []string `json:"arguments"`
}

type Fingerprints struct {
	Num0                       string `json:"0"`
	Num1                       string `json:"1"`
	Identity                   string `json:"identity"`
	SnykOrgProjectFindingV1    string `json:"snyk/org/project/finding/v1"`
	SnykOrgRepositoryFindingV1 string `json:"snyk/org/repository/finding/v1"`
	SnykAssetFindingV1         string `json:"snyk/asset/finding/v1"`
}

type SnykPolicyV1 struct {
	OriginalLevel    string `json:"originalLevel"`
	OriginalSeverity string `json:"originalSeverity"`
	Severity         string `json:"severity"`
}

type ResultProperties struct {
	PriorityScore        int `json:"priorityScore"`
	PriorityScoreFactors []struct {
		Label bool   `json:"label"`
		Type  string `json:"type"`
	} `json:"priorityScoreFactors"`
	IsAutofixable bool          `json:"isAutofixable"`
	Policy        *SnykPolicyV1 `json:"snykPolicy/v1,omitempty"`
}

type Result struct {
	RuleID       string           `json:"ruleId"`
	RuleIndex    int              `json:"ruleIndex"`
	Level        string           `json:"level"`
	Message      ResultMessage    `json:"message"`
	Locations    []Location       `json:"locations"`
	Fingerprints Fingerprints     `json:"fingerprints"`
	CodeFlows    []CodeFlow       `json:"codeFlows"`
	Properties   ResultProperties `json:"properties"`
	Suppressions []Suppression    `json:"suppressions"`
}

type ExampleCommitFix struct {
	CommitURL string `json:"commitURL"`
	Lines     []struct {
		Line       string `json:"line"`
		LineNumber int    `json:"lineNumber"`
		LineChange string `json:"lineChange"`
	} `json:"lines"`
}

type Help struct {
	Markdown string `json:"markdown"`
	Text     string `json:"text"`
}

type RuleProperties struct {
	Tags                      []string           `json:"tags"`
	Categories                []string           `json:"categories"`
	ExampleCommitFixes        []ExampleCommitFix `json:"exampleCommitFixes"`
	ExampleCommitDescriptions []string           `json:"exampleCommitDescriptions"`
	Precision                 string             `json:"precision"`
	RepoDatasetSize           int                `json:"repoDatasetSize"`
	Cwe                       []string           `json:"cwe"`
}

type DefaultConfiguration struct {
	Level string `json:"level"`
}

type ShortDescription struct {
	Text string `json:"text"`
}

type Rule struct {
	ID                   string               `json:"id"`
	Name                 string               `json:"name"`
	ShortDescription     ShortDescription     `json:"shortDescription"`
	DefaultConfiguration DefaultConfiguration `json:"defaultConfiguration"`
	Help                 Help                 `json:"help"`
	Properties           RuleProperties       `json:"properties"`
}

type Driver struct {
	Name            string `json:"name"`
	SemanticVersion string `json:"semanticVersion"`
	Version         string `json:"version"`
	Rules           []Rule `json:"rules"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type RunProperties struct {
	Coverage []struct {
		Files       int    `json:"files"`
		IsSupported bool   `json:"isSupported"`
		Lang        string `json:"lang"`
		Type        string `json:"type"`
	} `json:"coverage"`
}

type Run struct {
	Tool       Tool          `json:"tool"`
	Results    []Result      `json:"results"`
	Properties RunProperties `json:"properties"`
}

type Suppression struct {
	Guid          string                `json:"guid"`
	Justification string                `json:"justification"`
	Properties    SuppressionProperties `json:"properties"`
	Status        SuppresionStatus      `json:"status"`
}

type SuppressionProperties struct {
	Category   Category  `json:"category"`
	Expiration *string   `json:"expiration"`
	IgnoredOn  string    `json:"ignoredOn"` // https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html#_Toc141790703
	IgnoredBy  IgnoredBy `json:"ignoredBy"`
}

type Category string
type SuppresionStatus string

const (
	WontFix         Category         = "wont-fix"
	NotVulnerable   Category         = "not-vulnerable"
	TemporaryIgnore Category         = "temporary-ignore"
	UnderReview     SuppresionStatus = "underReview"
	Accepted        SuppresionStatus = "accepted"
	Rejected        SuppresionStatus = "rejected"
)

type IgnoredBy struct {
	Name  string  `json:"name"`
	Email *string `json:"email"`
}
