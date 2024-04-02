package analysis_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/code-client-go/internal/analysis"
	"github.com/snyk/code-client-go/sarif"
)

func TestAnalysis_RunAnalysis(t *testing.T) {
	actual, err := analysis.RunAnalysis()
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", actual.Status)
	assert.Contains(t, actual.Sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI, "scripts/db/migrations/20230811153738_add_generated_grouping_columns_to_collections_table.ts")
	assert.Nil(t, actual.Sarif.Runs[0].Results[0].Suppressions)
	assert.NotNil(t, actual.Sarif.Runs[0].Results[1].Suppressions)
	assert.Len(t, actual.Sarif.Runs[0].Results[1].Suppressions, 1)
	assert.Equal(t, "False positive", actual.Sarif.Runs[0].Results[1].Suppressions[0].Justification)
	assert.Equal(t, sarif.WontFix, actual.Sarif.Runs[0].Results[1].Suppressions[0].Properties.Category)
	assert.Equal(t, "13 days", *actual.Sarif.Runs[0].Results[1].Suppressions[0].Properties.Expiration)
	assert.Equal(t, "2024-02-23T16:08:25Z", actual.Sarif.Runs[0].Results[1].Suppressions[0].Properties.IgnoredOn)
	assert.Equal(t, "Neil M", actual.Sarif.Runs[0].Results[1].Suppressions[0].Properties.IgnoredBy.Name)
	assert.Equal(t, "test@test.io", *actual.Sarif.Runs[0].Results[1].Suppressions[0].Properties.IgnoredBy.Email)
}
