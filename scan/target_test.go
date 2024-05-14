package scan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTarget_pathOnly(t *testing.T) {
	expectedPath := "./"
	target, err := NewRepositoryTarget(expectedPath)
	assert.NoError(t, err)
	repoTarget, ok := target.(*RepositoryTarget)
	assert.True(t, ok)
	assert.NotEmpty(t, repoTarget.GetRepositoryUrl())
	assert.Equal(t, expectedPath, repoTarget.GetPath())
}

func TestTarget_pathToNonRepo(t *testing.T) {
	expectedPath := t.TempDir()
	target, err := NewRepositoryTarget(expectedPath)
	assert.Error(t, err)
	repoTarget, ok := target.(*RepositoryTarget)
	assert.True(t, ok)
	assert.Empty(t, repoTarget.GetRepositoryUrl())
	assert.Equal(t, expectedPath, repoTarget.GetPath())
}

func TestTarget_withRepoUrl(t *testing.T) {
	expectedRepoUrl := "https://myrepo.com/hello_world"
	expectedPath := "/hello_world"
	target, err := NewRepositoryTarget(expectedPath, WithRepositoryUrl("https://user:pass@myrepo.com/hello_world"))
	assert.NoError(t, err)
	repoTarget, ok := target.(*RepositoryTarget)
	assert.True(t, ok)
	assert.Equal(t, expectedRepoUrl, repoTarget.GetRepositoryUrl())
	assert.Equal(t, expectedPath, repoTarget.GetPath())
}
