package llm

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
}
