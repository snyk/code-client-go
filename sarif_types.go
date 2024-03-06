/*
 * © 2022 Snyk Limited All rights reserved.
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

package code_client_go

type SarifResponse struct {
	Type     string  `json:"type"`
	Progress float64 `json:"progress"`
	Status   string  `json:"status"`
	Timing   struct {
		FetchingCode int `json:"fetchingCode"`
		Queue        int `json:"queue"`
		Analysis     int `json:"analysis"`
	} `json:"timing"`
	Coverage []struct {
		Files       int    `json:"files"`
		IsSupported bool   `json:"isSupported"`
		Lang        string `json:"lang"`
	} `json:"coverage"`
	Sarif struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []Run  `json:"runs"`
	} `json:"sarif"`
}

type region struct {
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
	ArtifactLocation ArtifactLocation `json:"ArtifactLocation"`
	Region           region           `json:"region"`
}

type Location struct {
	ID               int              `json:"id"`
	PhysicalLocation PhysicalLocation `json:"PhysicalLocation"`
}

type ThreadFlowLocation struct {
	Location Location `json:"Location"`
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
	Num0 string `json:"0"`
	Num1 string `json:"1"`
}

type ResultProperties struct {
	PriorityScore        int `json:"priorityScore"`
	PriorityScoreFactors []struct {
		Label bool   `json:"label"`
		Type  string `json:"type"`
	} `json:"priorityScoreFactors"`
	IsAutofixable bool `json:"isAutofixable"`
}

type Result struct {
	RuleID       string           `json:"ruleId"`
	RuleIndex    int              `json:"ruleIndex"`
	Level        string           `json:"level"`
	Message      ResultMessage    `json:"message"`
	Locations    []Location       `json:"locations"`
	Fingerprints Fingerprints     `json:"Fingerprints"`
	CodeFlows    []CodeFlow       `json:"codeFlows"`
	Properties   ResultProperties `json:"properties"`
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
	Tags             []string `json:"tags"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"ShortDescription"`

	Help struct {
		Markdown string `json:"markdown"`
		Text     string `json:"text"`
	} `json:"Help"`

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
	ShortDescription     ShortDescription     `json:"ShortDescription"`
	DefaultConfiguration DefaultConfiguration `json:"DefaultConfiguration"`
	Help                 Help                 `json:"Help"`
	Properties           RuleProperties       `json:"properties"`
}

type Driver struct {
	Name            string `json:"name"`
	SemanticVersion string `json:"semanticVersion"`
	Version         string `json:"version"`
	Rules           []Rule `json:"rules"`
}

type Tool struct {
	Driver Driver `json:"Driver"`
}

type runProperties struct {
	Coverage []struct {
		Files       int    `json:"files"`
		IsSupported bool   `json:"isSupported"`
		Lang        string `json:"lang"`
	} `json:"coverage"`
}

type Run struct {
	Tool       Tool          `json:"Tool"`
	Results    []Result      `json:"results"`
	Properties runProperties `json:"RuleProperties"`
}
