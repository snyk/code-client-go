package codeClient_test

import (
	"testing"

	codeClient "github.com/snyk/code-client-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUploadAndAnalyze(t *testing.T) {
	actual, err := codeClient.UploadAndAnalyze()
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", actual.Status)
}
