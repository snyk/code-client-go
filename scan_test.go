package code_client_go_test

import (
	"github.com/snyk/code-client-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestUploadAndAnalyze(t *testing.T) {
	actual, err := code_client_go.UploadAndAnalyze()
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", actual.Status)
}
