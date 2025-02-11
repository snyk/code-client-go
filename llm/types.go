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
	Derivation        string            `json:"Derivation"`
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
	Diff string `json:"diff"`
}
