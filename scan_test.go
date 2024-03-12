package codeclient_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	codeClient "github.com/snyk/code-client-go"
)

func TestUploadAndAnalyze(t *testing.T) {
	actual, err := codeClient.UploadAndAnalyze()
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", actual.Status)
	assert.Contains(t, actual.Sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI, "src/main.ts")
	assert.Nil(t, actual.Sarif.Runs[0].Results[0].Suppressions)
	assert.NotNil(t, actual.Sarif.Runs[0].Results[1].Suppressions)
}
