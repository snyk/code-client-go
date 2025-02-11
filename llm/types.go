package llm

type explanationLength string

const (
	SHORT  explanationLength = "SHORT"
	MEDIUM explanationLength = "MEDIUM"
	LONG   explanationLength = "LONG"
)

type explainVulnerabilityRequest struct {
	RuleId            string            `json:"rule_key"`
	RuleMessage       string            `json:"rule_message"`
	Derivation        string            `json:"derivation"`
	ExplanationLength explanationLength `json:"explanation_length"`
}

type explainFixRequest struct {
	RuleId            string            `json:"rule_key"`
	Diff              string            `json:"diff"`
	ExplanationLength explanationLength `json:"explanation_length"`
}

type explainRequest struct {
	VulnExplanation *explainVulnerabilityRequest `json:"vuln_explanation,omitempty"`
	FixExplanation  *explainFixRequest           `json:"fix_explanation,omitempty"`
}

type explainResponse struct {
	Status      string `json:"status"`
	Explanation string `json:"explanation"`
}

type explainOptions struct {
	derivation  string
	ruleKey     string
	ruleMessage string
	diff        string
}
