package testutil

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog/log"
)

func SetupCustomTestRepo(t *testing.T, url string, targetCommit string, parentDir, repoDir string) (string, error) {
	t.Helper()
	if parentDir == "" {
		parentDir = t.TempDir()
	}
	if repoDir == "" {
		repoDir = "1"
	}
	absoluteCloneRepoDir := filepath.Join(parentDir, repoDir)
	cmd := []string{"clone", url, repoDir}
	log.Debug().Interface("cmd", cmd).Msg("clone command")
	clone := exec.Command("git", cmd...)
	clone.Dir = parentDir
	reset := exec.Command("git", "reset", "--hard", targetCommit)
	reset.Dir = absoluteCloneRepoDir

	clean := exec.Command("git", "clean", "--force")
	clean.Dir = absoluteCloneRepoDir

	output, err := clone.CombinedOutput()
	if err != nil {
		t.Fatal(err, "clone didn't work")
	}

	log.Debug().Msg(string(output))
	output, _ = reset.CombinedOutput()

	log.Debug().Msg(string(output))
	output, err = clean.CombinedOutput()

	log.Debug().Msg(string(output))
	return absoluteCloneRepoDir, err
}
