package main

import (
	"context"
	"fmt"
	"github.com/snyk/code-client-go/internal/util/testutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/form3tech-oss/f1/v2/pkg/f1"
	"github.com/form3tech-oss/f1/v2/pkg/f1/testing"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	codeClient "github.com/snyk/code-client-go"
	codeClientHTTP "github.com/snyk/code-client-go/http"
)

func main() {
	f1.New().Add("loadTest", setupMySuperFastLoadTest).Execute()
}

func setupMySuperFastLoadTest(t *testing.T) testing.RunFn {
	fmt.Println("Setup the scenario")

	tempDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cloneTargetDir, err := SetupCustomTestRepo(t, tempDir, "https://github.com/snyk-labs/nodejs-goof", "0336589")
	defer func(path string) { _ = os.RemoveAll(path) }(cloneTargetDir)
	if err != nil {
		t.Fatal(err)
	}
	files := sliceToChannel([]string{filepath.Join(cloneTargetDir, "app.js"), filepath.Join(cloneTargetDir, "utils.js")})

	t.Cleanup(func() {
		fmt.Println("Clean up the setup of the scenario")
		err := os.RemoveAll(cloneTargetDir)
		if err != nil {
			t.Fatal(err)
		}
	})

	runFn := func(t *testing.T) {
		fmt.Println("Run the test")

		logger := zerolog.New(os.Stdout).Level(zerolog.TraceLevel)
		instrumentor := testutil.NewTestInstrumentor()
		errorReporter := testutil.NewTestErrorReporter()
		config := testutil.NewTestConfig()
		httpClient := codeClientHTTP.NewHTTPClient(
			func() *http.Client {
				client := http.Client{
					Timeout:   time.Duration(180) * time.Second,
					Transport: TestAuthRoundTripper{http.DefaultTransport},
				}
				return &client
			},
			codeClientHTTP.WithRetryCount(1),
			codeClientHTTP.WithLogger(&logger),
		)

		codeScanner := codeClient.NewCodeScanner(
			config,
			httpClient,
			codeClient.WithLogger(&logger),
			codeClient.WithInstrumentor(instrumentor),
			codeClient.WithErrorReporter(errorReporter),
		)
		_, _, err = codeScanner.UploadAndAnalyze(context.Background(), uuid.New().String(), cloneTargetDir, files, map[string]bool{})
		if err != nil {
			t.Fatal(err)
		}

		// Register clean up function for each test which will be invoked in LIFO order after each iteration
		t.Cleanup(func() {
			fmt.Println("Clean up the test execution")
		})
	}

	return runFn
}

func SetupCustomTestRepo(t *testing.T, url string, tempDir string, targetCommit string) (string, error) {
	repoDir := "1"
	absoluteCloneRepoDir := filepath.Join(tempDir, repoDir)
	cmd := []string{"clone", url, repoDir}
	log.Debug().Interface("cmd", cmd).Msg("clone command")
	clone := exec.Command("git", cmd...)
	clone.Dir = tempDir
	reset := exec.Command("git", "reset", "--hard", targetCommit)
	reset.Dir = absoluteCloneRepoDir

	clean := exec.Command("git", "clean", "--force")
	clean.Dir = absoluteCloneRepoDir

	output, err := clone.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}

	log.Debug().Msg(string(output))
	output, _ = reset.CombinedOutput()

	log.Debug().Msg(string(output))
	output, err = clean.CombinedOutput()

	log.Debug().Msg(string(output))
	return absoluteCloneRepoDir, err
}

type TestAuthRoundTripper struct {
	http.RoundTripper
}

func (tart TestAuthRoundTripper) RoundTrip(req *http.Request) (res *http.Response, e error) {
	token := os.Getenv("LOAD_TEST_TOKEN")
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
	req.Header.Set("session_token", token)
	return tart.RoundTripper.RoundTrip(req)
}

func sliceToChannel(slice []string) <-chan string {
	ch := make(chan string)
	go func() {
		defer close(ch)
		for _, s := range slice {
			ch <- s
		}
	}()

	return ch
}
