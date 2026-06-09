package code_workflow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodeIssues_listCodeIssuesWithExplicitProjectID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/rest/orgs/"+testOrg+"/issues", r.URL.Path)
		assert.Equal(t, testProjectID, r.URL.Query().Get("scan_item.id"))
		assert.Equal(t, "project", r.URL.Query().Get("scan_item.type"))
		assert.Equal(t, "code", r.URL.Query().Get("type"))
		assert.Equal(t, "false", r.URL.Query().Get("ignored"))

		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{
			"data": [
				{
					"type": "issue",
					"id": "issue-1",
					"attributes": {
						"title": "Hardcoded secret",
						"effective_severity_level": "high",
						"status": "open",
						"ignored": false,
						"file_path": "src/config.ts"
					}
				}
			],
			"links": {}
		}`))
	}))
	defer server.Close()

	client := newCodeProjectResolverClient(server.URL, server.Client())
	output, err := listCodeIssues(context.Background(), client, codeIssuesOptions{
		Org:       testOrg,
		ProjectID: testProjectID,
		Ignored:   "false",
		Limit:     100,
	}, nilLogger())

	require.NoError(t, err)
	require.Len(t, output.Issues, 1)
	assert.Equal(t, testProjectID, output.Project.ID)
	assert.Nil(t, output.ResolvedFrom)
	assert.Equal(t, "issue-1", output.Issues[0].ID)
	assert.Equal(t, "Hardcoded secret", output.Issues[0].Title)
	assert.Equal(t, "high", output.Issues[0].Severity)
	assert.Equal(t, "src/config.ts", output.Issues[0].Location)
}

func TestCodeIssues_resolvesProjectThenListsIssues(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path+"?"+r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/vnd.api+json")

		switch r.URL.Path {
		case "/rest/orgs/" + testOrg + "/targets":
			_, _ = w.Write([]byte(`{"data":[{"type":"target","id":"` + testTargetID + `","attributes":{"remote_url":"https://github.com/snyk/example.git"}}],"links":{}}`))
		case "/rest/orgs/" + testOrg + "/projects":
			_, _ = w.Write([]byte(`{"data":[{"type":"project","id":"` + testProjectID + `","attributes":{"name":"example","type":"sast","target_reference":"main","target_file":""}}],"links":{}}`))
		case "/rest/orgs/" + testOrg + "/issues":
			assert.Equal(t, testProjectID, r.URL.Query().Get("scan_item.id"))
			_, _ = w.Write([]byte(`{"data":[],"links":{}}`))
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := newCodeProjectResolverClient(server.URL, server.Client())
	output, err := listCodeIssues(context.Background(), client, codeIssuesOptions{
		Org:             testOrg,
		RemoteRepoURL:   "https://github.com/snyk/example.git",
		TargetReference: "main",
		Ignored:         "false",
		Limit:           100,
	}, nilLogger())

	require.NoError(t, err)
	assert.Equal(t, testProjectID, output.Project.ID)
	assert.Equal(t, "https://github.com/snyk/example.git", output.ResolvedFrom.RemoteRepoURL)
	assert.Equal(t, "main", output.ResolvedFrom.TargetReference)
	assert.Len(t, seen, 3)
}

func TestCodeIssues_limitMustMatchIssuesAPIMinimum(t *testing.T) {
	_, err := getCodeIssuesOptions(configurationForCodeIssues(map[string]interface{}{
		configuration.ORGANIZATION: testOrg,
		ConfigurationLimit:         5,
	}))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "limit must be between 10 and 100")
}

func TestCodeIssues_fetchAllPages(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		assert.Equal(t, "/rest/orgs/"+testOrg+"/issues", r.URL.Path)
		w.Header().Set("Content-Type", "application/vnd.api+json")

		if r.URL.Query().Get("starting_after") == "" {
			next := "/rest/orgs/" + testOrg + "/issues?" + url.Values{"starting_after": []string{"cursor-1"}}.Encode()
			_, _ = w.Write([]byte(`{"data":[{"type":"issue","id":"issue-1","attributes":{"severity":"low"}}],"links":{"next":"` + next + `"}}`))
			return
		}

		assert.Equal(t, "cursor-1", r.URL.Query().Get("starting_after"))
		_, _ = w.Write([]byte(`{"data":[{"type":"issue","id":"issue-2","attributes":{"severity":"critical"}}],"links":{}}`))
	}))
	defer server.Close()

	client := newCodeProjectResolverClient(server.URL, server.Client())
	issues, complete, nextPage, err := client.listIssues(context.Background(), testOrg, testProjectID, "all", 100, true, nilLogger())

	require.NoError(t, err)
	assert.True(t, complete)
	assert.Empty(t, nextPage)
	assert.Len(t, issues, 2)
	assert.Equal(t, 2, requests)
}

func TestCodeIssues_renderJSONPreservesRawResource(t *testing.T) {
	resource := jsonAPIResource{
		ID:   "issue-1",
		Type: "issue",
		Attributes: map[string]interface{}{
			"title":                    "Hardcoded secret",
			"effective_severity_level": "high",
		},
	}

	issue := normalizeIssue(resource, testProjectID)
	bytes, err := json.Marshal(issue)

	require.NoError(t, err)
	assert.Contains(t, string(bytes), `"raw"`)
	assert.Contains(t, string(bytes), `"effective_severity_level"`)
}

func TestCodeIssues_extractsNestedSourceLocation(t *testing.T) {
	issue := normalizeIssue(jsonAPIResource{
		ID:   "issue-1",
		Type: "issue",
		Attributes: map[string]interface{}{
			"coordinates": []interface{}{
				map[string]interface{}{
					"representations": []interface{}{
						map[string]interface{}{
							"sourceLocation": map[string]interface{}{
								"file": "routes/index.js",
								"region": map[string]interface{}{
									"start": map[string]interface{}{"line": float64(52)},
								},
							},
						},
					},
				},
			},
		},
	}, testProjectID)

	assert.Equal(t, "routes/index.js:52", issue.Location)
}

func TestCodeIssues_renderTable(t *testing.T) {
	ignored := false
	table := renderCodeIssuesTable(codeIssuesOutput{
		Project:    &projectSummary{ID: testProjectID, Name: "example"},
		IssueCount: 1,
		Complete:   true,
		Issues: []codeIssue{
			{
				ID:       "issue-1",
				Title:    "Hardcoded secret",
				Severity: "high",
				Location: "src/config.ts",
				Ignored:  &ignored,
			},
		},
	})

	assert.Contains(t, table, "Project: "+testProjectID+" (example)")
	assert.Contains(t, table, "Hardcoded secret")
	assert.True(t, strings.Contains(table, "issue-1"))
}

func configurationForCodeIssues(values map[string]interface{}) configuration.Configuration {
	config := configuration.New()
	for key, value := range values {
		config.Set(key, value)
	}
	return config
}
