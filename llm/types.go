package llm

// AutofixResponse is the json-based structure to which we can translate the results of the HTTP
// request to Autofix upstream.
type AutofixResponse struct {
	Status             string                     `json:"status"`
	AutofixSuggestions []autofixResponseSingleFix `json:"fixes"`
}
type autofixResponseSingleFix struct {
	Id          string `json:"id"`
	Value       string `json:"value"`
	Explanation string `json:"explanation"`
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
	Type     string `json:"type"`
	Hash     string `json:"hash"`
	Shard    string `json:"shard"`
	FilePath string `json:"filePath"`
	RuleId   string `json:"ruleId"`
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
	LineNum    int

	Host                string
	CodeRequestContext  CodeRequestContext
	IdeExtensionDetails AutofixIdeExtensionDetails
}

type AutofixFeedbackOptions struct {
	FixID  string
	Result string

	Host                string
	CodeRequestContext  CodeRequestContext
	IdeExtensionDetails AutofixIdeExtensionDetails
}

type AutofixEventDetails struct {
	FixId string `json:"fixId"`
}

type AutofixUserEvent struct {
	AnalysisContext     CodeRequestContext         `json:"analysisContext"`
	Channel             string                     `json:"channel"`
	EventType           string                     `json:"eventType"`
	EventDetails        AutofixEventDetails        `json:"eventDetails"`
	IdeExtensionDetails AutofixIdeExtensionDetails `json:"ideExtensionDetails"`
}
