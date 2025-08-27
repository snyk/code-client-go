package llm

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
	"github.com/rs/zerolog"
)

func (s *AutofixResponse) toUnifiedDiffSuggestions(logger *zerolog.Logger, baseDir string, filePath string) []AutofixUnifiedDiffSuggestion {
	var fixSuggestions []AutofixUnifiedDiffSuggestion
	for _, suggestion := range s.AutofixSuggestions {
		decodedPath, unifiedDiff := getPathAndUnifiedDiff(logger, baseDir, filePath, suggestion.Value)
		if decodedPath == "" || unifiedDiff == "" {
			continue
		}

		d := AutofixUnifiedDiffSuggestion{
			FixId:               suggestion.Id,
			UnifiedDiffsPerFile: map[string]string{},
		}

		d.UnifiedDiffsPerFile[decodedPath] = unifiedDiff
		fixSuggestions = append(fixSuggestions, d)
	}
	return fixSuggestions
}

func getPathAndUnifiedDiff(zeroLogger *zerolog.Logger, baseDir string, filePath string, newText string) (decodedPath string, unifiedDiff string) {
	logger := zeroLogger.With().Str("method", "getUnifiedDiff").Logger()

	decodedPath, err := url.PathUnescape(filepath.Join(baseDir, filePath))
	if err != nil {
		logger.Err(err).Msgf("cannot decode filePath %s", filePath)
		return
	}
	logger.Debug().Msgf("File decodedPath %s", decodedPath)

	fileContent, err := os.ReadFile(decodedPath)
	if err != nil {
		logger.Err(err).Msgf("cannot read fileContent %s", decodedPath)
		return
	}

	// Workaround: AI Suggestion API only returns \n new lines. It doesn't consider carriage returns.
	contentBefore := strings.ReplaceAll(string(fileContent), "\r\n", "\n")
	edits := myers.ComputeEdits(span.URIFromPath(decodedPath), contentBefore, newText)
	unifiedDiff = fmt.Sprint(gotextdiff.ToUnified(decodedPath, decodedPath+"fixed", contentBefore, edits))

	return decodedPath, unifiedDiff
}
