package llm

import "net/url"

type explanationLength string

const (
	SHORT  explanationLength = "SHORT"
	MEDIUM explanationLength = "MEDIUM"
	LONG   explanationLength = "LONG"
)

type explainVulnerabilityRequest struct {
	RuleId            string            `json:"rule_id"`
	RuleMessage       string            `json:"rule_message"`
	Derivation        string            `json:"Derivation"`
	ExplanationLength explanationLength `json:"explanation_length"`
}

type explainFixRequest struct {
	RuleId            string            `json:"rule_id"`
	Diffs             []string          `json:"diffs"`
	ExplanationLength explanationLength `json:"explanation_length"`
}

type explainResponse struct {
	Status      string       `json:"status"`
	Explanation Explanations `json:"explanation"`
}
type Explanations map[string]string
type ExplainOptions struct {
	// Derivation = Code Flow
	// const derivationLineNumbers: Set<number> = new Set<number>();
	//          for (const markerLocation of suggestion.markers!) {
	//            for (const markerPos of markerLocation.pos) {
	//              const lines = markerPos.rows;
	//              for (const line of lines) {
	//                derivationLineNumbers.add(line + 1);
	//              }
	//            }
	//            markerLocation.pos;
	//          }
	//          console.log('Derivation lines: ', ...derivationLineNumbers);
	//
	//          const derivationLines: string[] = [];
	//          const fileLines: string[] = fileContent.split('\n');
	//          for (const derivationLineNumber of derivationLineNumbers) {
	//            derivationLines.push(fileLines.at(derivationLineNumber - 1)!);
	//          }
	//          let Derivation = derivationLines.join(',');
	//          Derivation = Derivation.replace(/\t/g, '  ');
	//          console.log('Derivation: ', Derivation);
	Derivation string `json:"derivation"`

	// vulnerability name from Snyk Code (rule)
	RuleKey string `json:"rule_key"`

	// Snyk Code message for the vulnerability
	RuleMessage string `json:"rule_message"`

	// fix difference
	Diffs []string `json:"diffs"`

	// Endpoint to call
	Endpoint *url.URL `json:"endpoint"`
}

// AutofixResponse is the json-based structure to which we can translate the results of the HTTP
// request to Autofix upstream.
type AutofixResponse struct {
	Status             string                     `json:"status"`
	AutofixSuggestions []autofixResponseSingleFix `json:"fixes"`
}
type autofixResponseSingleFix struct {
	Id    string `json:"id"`
	Value string `json:"value"`
}

// AutofixUnifiedDiffSuggestion represents the diff between the original and the fixed source code.
type AutofixUnifiedDiffSuggestion struct {
	FixId               string            `json:"fixId"`
	UnifiedDiffsPerFile map[string]string `json:"unifiedDiffsPerFile"`
	FullTextPerFile     map[string]string `json:"fullTextPerFile"`
	Explanation         string            `json:"explanation"`
}

type AutofixStatus struct {
	Message string
}

type AutofixRequestKey struct {
	Type     string         `json:"type"`
	Hash     string         `json:"hash"`
	Shard    string         `json:"shard"`
	FilePath string 		`json:"filePath"`
	RuleId   string         `json:"ruleId"`
	// 1-based to comply with Sarif and Code API, see
	// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html#_Ref493492556
	LineNum int `json:"lineNum"`
}

type AutofixIdeExtensionDetails struct {
	IdeName          string `json:"ideName"`
	IdeVersion       string `json:"ideVersion"`
	ExtensionName    string `json:"extensionName"`
	ExtensionVersion string `json:"extensionVersion"`
}

type AutofixRequest struct {
	Key                 AutofixRequestKey          `json:"key"`
	AnalysisContext     CodeRequestContext         `json:"analysisContext"`
	IdeExtensionDetails AutofixIdeExtensionDetails `json:"ideExtensionDetails"`
}

type CodeRequestContextOrg struct {
	Name        string          `json:"name"`
	DisplayName string          `json:"displayName"`
	PublicId    string          `json:"publicId"`
	Flags       map[string]bool `json:"flags"`
}

type CodeRequestContext struct {
	Initiator string                `json:"initiator"`
	Flow      string                `json:"flow,omitempty"`
	Org       CodeRequestContextOrg `json:"org,omitempty"`
}

type AutofixOptions struct {
	RuleID     string
	BundleHash string
	ShardKey   string
	BaseDir    string
	FilePath   string
	LineNum	   int

	Endpoint                   *url.URL
	CodeRequestContext         CodeRequestContext
	IdeExtensionDetails        AutofixIdeExtensionDetails
}


type AutofixFeedbackOptions struct {
	FixID      string
	Result	   string

	Endpoint                   *url.URL
	CodeRequestContext         CodeRequestContext
	IdeExtensionDetails        AutofixIdeExtensionDetails
}
