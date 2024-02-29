package fake_test

import (
	"github.com/snyk/code-client-go/pkg/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGetCodeScanResults(t *testing.T) {
	actual, err := fake.GetCodeScanResults()
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", actual.Status)
}
