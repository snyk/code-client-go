package code_workflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testOrg       = "00000000-0000-0000-0000-000000000001"
	testProjectID = "00000000-0000-0000-0000-000000000002"
	testTargetID  = "00000000-0000-0000-0000-000000000003"
)

func TestCodeProjectResolution_usesExplicitProjectID(t *testing.T) {
	client := newCodeProjectResolverClient("https://api.example.test", http.DefaultClient)
	project, resolved, err := resolveCodeProject(context.Background(), client, codeProjectResolutionOptions{
		Org:       testOrg,
		ProjectID: testProjectID,
	}, nilLogger())

	require.NoError(t, err)
	assert.Equal(t, testProjectID, project.ID)
	assert.Nil(t, resolved)
}

func TestCodeProjectResolution_resolvesProjectFromRepoAndTargetReference(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path+"?"+r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/vnd.api+json")

		switch r.URL.Path {
		case "/rest/orgs/" + testOrg + "/targets":
			assert.Equal(t, "https://github.com/snyk/example.git", r.URL.Query().Get("url"))
			assert.Equal(t, "true", r.URL.Query().Get("exclude_empty"))
			_, _ = w.Write([]byte(`{"data":[{"type":"target","id":"` + testTargetID + `","attributes":{"remote_url":"https://github.com/snyk/example.git"}}],"links":{}}`))
		case "/rest/orgs/" + testOrg + "/projects":
			assert.Equal(t, testTargetID, r.URL.Query().Get("target_id"))
			assert.Equal(t, "main", r.URL.Query().Get("target_reference"))
			assert.Equal(t, codeProjectType, r.URL.Query().Get("types"))
			_, _ = w.Write([]byte(`{"data":[{"type":"project","id":"` + testProjectID + `","attributes":{"name":"example","type":"sast","target_reference":"main","target_file":""}}],"links":{}}`))
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := newCodeProjectResolverClient(server.URL, server.Client())
	project, resolved, err := resolveCodeProject(context.Background(), client, codeProjectResolutionOptions{
		Org:             testOrg,
		RemoteRepoURL:   "https://github.com/snyk/example.git",
		TargetReference: "main",
		Limit:           100,
	}, nilLogger())

	require.NoError(t, err)
	assert.Equal(t, testProjectID, project.ID)
	assert.Equal(t, "example", project.Name)
	assert.Equal(t, "https://github.com/snyk/example.git", resolved.RemoteRepoURL)
	assert.Equal(t, "main", resolved.TargetReference)
	assert.Len(t, seen, 2)
}

func TestCodeProjectResolution_resolvesProjectFromSSHRepoURLUsingHTTPSCandidate(t *testing.T) {
	var targetLookups []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")

		switch r.URL.Path {
		case "/rest/orgs/" + testOrg + "/targets":
			targetLookups = append(targetLookups, r.URL.Query().Get("url"))
			if r.URL.Query().Get("url") == "https://github.com/snyk/example" {
				_, _ = w.Write([]byte(`{"data":[{"type":"target","id":"` + testTargetID + `"}],"links":{}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":[],"links":{}}`))
		case "/rest/orgs/" + testOrg + "/projects":
			assert.Equal(t, testTargetID, r.URL.Query().Get("target_id"))
			assert.Equal(t, codeProjectType, r.URL.Query().Get("types"))
			_, _ = w.Write([]byte(`{"data":[{"type":"project","id":"` + testProjectID + `","attributes":{"name":"example","type":"sast","target_reference":"main"}}],"links":{}}`))
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := newCodeProjectResolverClient(server.URL, server.Client())
	project, resolved, err := resolveCodeProject(context.Background(), client, codeProjectResolutionOptions{
		Org:             testOrg,
		RemoteRepoURL:   "git@github.com:snyk/example.git",
		TargetReference: "main",
		Limit:           100,
	}, nilLogger())

	require.NoError(t, err)
	assert.Equal(t, testProjectID, project.ID)
	assert.Equal(t, "https://github.com/snyk/example", resolved.RemoteRepoURL)
	assert.Equal(t, []string{
		"git@github.com:snyk/example.git",
		"https://github.com/snyk/example.git",
		"https://github.com/snyk/example",
	}, targetLookups)
}

func TestCodeProjectResolution_fallsBackToProjectWithoutTargetReference(t *testing.T) {
	projectLookups := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")

		switch r.URL.Path {
		case "/rest/orgs/" + testOrg + "/targets":
			_, _ = w.Write([]byte(`{"data":[{"type":"target","id":"` + testTargetID + `"}],"links":{}}`))
		case "/rest/orgs/" + testOrg + "/projects":
			projectLookups++
			if projectLookups == 1 {
				assert.Equal(t, "main", r.URL.Query().Get("target_reference"))
				_, _ = w.Write([]byte(`{"data":[],"links":{}}`))
				return
			}
			assert.Empty(t, r.URL.Query().Get("target_reference"))
			assert.Equal(t, codeProjectType, r.URL.Query().Get("types"))
			_, _ = w.Write([]byte(`{"data":[{"type":"project","id":"` + testProjectID + `","attributes":{"name":"example","type":"sast"}}],"links":{}}`))
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := newCodeProjectResolverClient(server.URL, server.Client())
	project, _, err := resolveCodeProject(context.Background(), client, codeProjectResolutionOptions{
		Org:             testOrg,
		RemoteRepoURL:   "https://github.com/snyk/example.git",
		TargetReference: "main",
		Limit:           100,
	}, nilLogger())

	require.NoError(t, err)
	assert.Equal(t, testProjectID, project.ID)
	assert.Equal(t, 2, projectLookups)
}

func TestCodeProjectResolution_multipleProjectsRequiresExplicitProjectID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		switch r.URL.Path {
		case "/rest/orgs/" + testOrg + "/targets":
			_, _ = w.Write([]byte(`{"data":[{"type":"target","id":"` + testTargetID + `"}],"links":{}}`))
		case "/rest/orgs/" + testOrg + "/projects":
			_, _ = w.Write([]byte(`{
				"data": [
					{"type":"project","id":"00000000-0000-0000-0000-000000000004","attributes":{"name":"one","target_reference":"main"}},
					{"type":"project","id":"00000000-0000-0000-0000-000000000005","attributes":{"name":"two","target_reference":"main"}}
				],
				"links": {}
			}`))
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := newCodeProjectResolverClient(server.URL, server.Client())
	_, _, err := resolveCodeProject(context.Background(), client, codeProjectResolutionOptions{
		Org:             testOrg,
		RemoteRepoURL:   "https://github.com/snyk/example.git",
		TargetReference: "main",
		Limit:           100,
	}, nilLogger())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "multiple Snyk Code projects matched")
	assert.Contains(t, err.Error(), "--project-id")
	assert.Contains(t, err.Error(), "one")
	assert.Contains(t, err.Error(), "two")
}

func TestCodeProjectResolution_fetchesAllTargetPages(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		assert.Equal(t, "/rest/orgs/"+testOrg+"/targets", r.URL.Path)
		w.Header().Set("Content-Type", "application/vnd.api+json")

		if r.URL.Query().Get("starting_after") == "" {
			next := "/rest/orgs/" + testOrg + "/targets?" + url.Values{"starting_after": []string{"cursor-1"}}.Encode()
			_, _ = w.Write([]byte(`{"data":[{"type":"target","id":"target-1"}],"links":{"next":"` + next + `"}}`))
			return
		}

		assert.Equal(t, "cursor-1", r.URL.Query().Get("starting_after"))
		_, _ = w.Write([]byte(`{"data":[{"type":"target","id":"target-2"}],"links":{}}`))
	}))
	defer server.Close()

	client := newCodeProjectResolverClient(server.URL, server.Client())
	targets, err := client.listTargets(context.Background(), testOrg, "https://github.com/snyk/example.git", 100, true, nilLogger())

	require.NoError(t, err)
	assert.Len(t, targets, 2)
	assert.Equal(t, 2, requests)
}

func TestCodeProjectResolution_repositoryURLCandidates(t *testing.T) {
	assert.Equal(t, []string{
		"git@github.com:snyk/example.git",
		"https://github.com/snyk/example.git",
		"https://github.com/snyk/example",
	}, repositoryURLCandidates("git@github.com:snyk/example.git"))

	assert.Equal(t, []string{
		"https://github.com/snyk/example.git",
		"https://github.com/snyk/example",
	}, repositoryURLCandidates("https://github.com/snyk/example.git"))
}

func TestCodeProjectResolution_renderProjectCandidates(t *testing.T) {
	table := renderProjectCandidates([]projectSummary{
		{ID: testProjectID, Name: "example", TargetReference: "main"},
	})

	assert.Contains(t, table, testProjectID)
	assert.Contains(t, table, "example")
	assert.True(t, strings.Contains(table, "main"))
}

func nilLogger() *zerolog.Logger {
	logger := zerolog.Nop()
	return &logger
}
