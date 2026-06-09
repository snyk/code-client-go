package code_workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/internal/util"
)

const (
	codeProjectResolverAPIVersion = "2025-11-05"
	defaultProjectResolutionLimit = 100
	codeProjectType               = "sast"
)

type codeProjectResolutionOptions struct {
	Org             string
	InputPath       string
	ProjectID       string
	RemoteRepoURL   string
	TargetReference string
	Limit           int
	FetchAll        bool
}

type resolvedFrom struct {
	RemoteRepoURL   string `json:"remoteRepoUrl,omitempty"`
	TargetReference string `json:"targetReference,omitempty"`
}

type projectSummary struct {
	ID              string `json:"id"`
	Name            string `json:"name,omitempty"`
	Type            string `json:"type,omitempty"`
	TargetReference string `json:"targetReference,omitempty"`
	TargetFile      string `json:"targetFile,omitempty"`
	TargetID        string `json:"targetId,omitempty"`
}

type codeProjectResolverClient struct {
	apiURL     string
	httpClient *http.Client
}

type pagedResources struct {
	Data  []jsonAPIResource `json:"data"`
	Links jsonAPILinks      `json:"links"`
}

type jsonAPILinks struct {
	Next json.RawMessage `json:"next,omitempty"`
}

type jsonAPIResource struct {
	ID            string                 `json:"id"`
	Type          string                 `json:"type"`
	Attributes    map[string]interface{} `json:"attributes,omitempty"`
	Relationships map[string]interface{} `json:"relationships,omitempty"`
}

func newCodeProjectResolverClient(apiURL string, httpClient *http.Client) *codeProjectResolverClient {
	return &codeProjectResolverClient{
		apiURL:     strings.TrimRight(apiURL, "/"),
		httpClient: httpClient,
	}
}

func resolveCodeProject(ctx context.Context, client *codeProjectResolverClient, options codeProjectResolutionOptions, logger *zerolog.Logger) (projectSummary, *resolvedFrom, error) {
	if options.ProjectID != "" {
		logger.Debug().Str("projectID", options.ProjectID).Msg("Using explicit Snyk project ID")
		return projectSummary{ID: options.ProjectID}, nil, nil
	}

	if options.InputPath == "" {
		options.InputPath = "."
	}
	if options.Limit == 0 {
		options.Limit = defaultProjectResolutionLimit
	}

	repoURL, targetReference, err := resolveLocalProjectContext(options, logger)
	if err != nil {
		return projectSummary{}, nil, err
	}

	targets, matchedRepoURL, err := resolveTargets(ctx, client, options, repoURL, logger)
	if err != nil {
		return projectSummary{}, nil, err
	}

	projects, err := resolveCodeProjects(ctx, client, options, targets, targetReference, logger)
	if err != nil {
		return projectSummary{}, nil, err
	}

	resolved := &resolvedFrom{RemoteRepoURL: matchedRepoURL, TargetReference: targetReference}
	project, err := selectResolvedProject(projects, repoURL, targetReference, logger)
	if err != nil {
		return projectSummary{}, resolved, err
	}
	return project, resolved, nil
}

func resolveLocalProjectContext(options codeProjectResolutionOptions, logger *zerolog.Logger) (string, string, error) {
	repoURL := options.RemoteRepoURL
	if repoURL == "" {
		logger.Debug().Str("inputPath", options.InputPath).Msg("Inferring git remote repository URL")
		resolvedURL, err := util.GetRepositoryUrl(options.InputPath)
		if err != nil {
			return "", "", fmt.Errorf("could not infer remote repository URL from %q; pass --remote-repo-url or --project-id: %w", options.InputPath, err)
		}
		repoURL = resolvedURL
	}
	logger.Debug().Str("remoteRepoURL", repoURL).Msg("Resolved git remote repository URL")

	targetReference := options.TargetReference
	if targetReference == "" {
		logger.Debug().Str("inputPath", options.InputPath).Msg("Inferring git target reference")
		branch, err := util.GetBranchName(options.InputPath)
		if err != nil {
			return "", "", fmt.Errorf("could not infer target reference from %q; pass --target-reference or --project-id: %w", options.InputPath, err)
		}
		targetReference = branch
	}
	logger.Debug().Str("targetReference", targetReference).Msg("Resolved git target reference")
	return repoURL, targetReference, nil
}

func resolveTargets(ctx context.Context, client *codeProjectResolverClient, options codeProjectResolutionOptions, repoURL string, logger *zerolog.Logger) ([]jsonAPIResource, string, error) {
	repoURLCandidates := repositoryURLCandidates(repoURL)
	logger.Debug().Strs("remoteRepoURLCandidates", repoURLCandidates).Msg("Resolving Snyk targets from repository URL candidates")

	for _, candidate := range repoURLCandidates {
		targets, err := client.listTargets(ctx, options.Org, candidate, options.Limit, options.FetchAll, logger)
		if err != nil {
			return nil, "", err
		}
		logger.Debug().
			Str("remoteRepoURL", candidate).
			Int("targets", len(targets)).
			Msg("Resolved matching Snyk targets for repository URL candidate")
		if len(targets) > 0 {
			return dedupeResourcesByID(targets), candidate, nil
		}
	}

	return nil, "", fmt.Errorf("no Snyk targets matched remote repository URL %q; tried %s; pass --remote-repo-url or --project-id", repoURL, strings.Join(repoURLCandidates, ", "))
}

func resolveCodeProjects(ctx context.Context, client *codeProjectResolverClient, options codeProjectResolutionOptions, targets []jsonAPIResource, targetReference string, logger *zerolog.Logger) ([]projectSummary, error) {
	projects, err := listProjectsForTargets(ctx, client, options, targets, targetReference, "Resolved matching Snyk Code projects for target", logger)
	if err != nil {
		return nil, err
	}
	if len(projects) > 0 || targetReference == "" {
		return projects, nil
	}

	logger.Debug().
		Str("targetReference", targetReference).
		Msg("No Snyk Code projects matched target reference; retrying without target_reference")
	return listProjectsForTargets(ctx, client, options, targets, "", "Resolved matching Snyk Code projects for target without target_reference", logger)
}

func listProjectsForTargets(ctx context.Context, client *codeProjectResolverClient, options codeProjectResolutionOptions, targets []jsonAPIResource, targetReference string, message string, logger *zerolog.Logger) ([]projectSummary, error) {
	var projects []projectSummary
	for _, target := range targets {
		targetProjects, err := client.listProjects(ctx, options.Org, target.ID, targetReference, options.Limit, options.FetchAll, logger)
		if err != nil {
			return nil, err
		}
		logger.Debug().
			Str("targetID", target.ID).
			Int("projects", len(targetProjects)).
			Msg(message)
		projects = append(projects, targetProjects...)
	}
	return projects, nil
}

func selectResolvedProject(projects []projectSummary, repoURL string, targetReference string, logger *zerolog.Logger) (projectSummary, error) {
	switch len(projects) {
	case 0:
		return projectSummary{}, fmt.Errorf("no Snyk Code projects matched remote repository URL %q and target reference %q; pass --project-id to select a project explicitly", repoURL, targetReference)
	case 1:
		logger.Debug().
			Str("projectID", projects[0].ID).
			Str("projectName", projects[0].Name).
			Str("targetReference", projects[0].TargetReference).
			Msg("Resolved single Snyk Code project")
		return projects[0], nil
	default:
		logger.Debug().Int("projects", len(projects)).Msg("Multiple Snyk Code projects matched local context")
		return projectSummary{}, fmt.Errorf("multiple Snyk Code projects matched remote repository URL %q and target reference %q; rerun with --project-id:\n%s", repoURL, targetReference, renderProjectCandidates(projects))
	}
}

func dedupeResourcesByID(resources []jsonAPIResource) []jsonAPIResource {
	deduped := make([]jsonAPIResource, 0, len(resources))
	seen := map[string]struct{}{}
	for _, resource := range resources {
		if _, ok := seen[resource.ID]; ok {
			continue
		}
		seen[resource.ID] = struct{}{}
		deduped = append(deduped, resource)
	}
	return deduped
}

func (c *codeProjectResolverClient) listTargets(ctx context.Context, org string, repoURL string, limit int, fetchAll bool, logger *zerolog.Logger) ([]jsonAPIResource, error) {
	params := url.Values{}
	params.Set("version", codeProjectResolverAPIVersion)
	params.Set("url", repoURL)
	params.Set("limit", strconv.Itoa(limit))
	params.Set("exclude_empty", "true")

	return c.getAll(ctx, path.Join("rest", "orgs", org, "targets"), params, fetchAll, logger)
}

func (c *codeProjectResolverClient) listProjects(ctx context.Context, org string, targetID string, targetReference string, limit int, fetchAll bool, logger *zerolog.Logger) ([]projectSummary, error) {
	params := url.Values{}
	params.Set("version", codeProjectResolverAPIVersion)
	params.Set("target_id", targetID)
	if targetReference != "" {
		params.Set("target_reference", targetReference)
	}
	params.Set("types", codeProjectType)
	params.Set("limit", strconv.Itoa(limit))

	resources, err := c.getAll(ctx, path.Join("rest", "orgs", org, "projects"), params, fetchAll, logger)
	if err != nil {
		return nil, err
	}

	projects := make([]projectSummary, 0, len(resources))
	for _, resource := range resources {
		projects = append(projects, normalizeProject(resource, targetID))
	}
	return projects, nil
}

func (c *codeProjectResolverClient) getAll(ctx context.Context, endpointPath string, params url.Values, fetchAll bool, logger *zerolog.Logger) ([]jsonAPIResource, error) {
	resources, nextPage, err := c.getPage(ctx, endpointPath, params, logger)
	if err != nil {
		return nil, err
	}
	if !fetchAll {
		return resources, nil
	}

	allResources := append([]jsonAPIResource{}, resources...)
	for nextPage != "" {
		params.Set("starting_after", nextPage)
		resources, nextPage, err = c.getPage(ctx, endpointPath, params, logger)
		if err != nil {
			return allResources, err
		}
		allResources = append(allResources, resources...)
	}
	return allResources, nil
}

func (c *codeProjectResolverClient) getPage(ctx context.Context, endpointPath string, params url.Values, logger *zerolog.Logger) ([]jsonAPIResource, string, error) {
	endpoint, err := url.Parse(c.apiURL)
	if err != nil {
		return nil, "", err
	}
	endpoint.Path = path.Join(endpoint.Path, endpointPath)
	endpoint.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/vnd.api+json")

	logger.Debug().
		Str("method", http.MethodGet).
		Str("path", endpoint.Path).
		Str("query", endpoint.RawQuery).
		Msg("Calling Snyk API")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, "", fmt.Errorf("Snyk API request failed: GET %s returned %d: %s", endpoint.Path, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var decoded pagedResources
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, "", fmt.Errorf("failed to decode Snyk API response from %s: %w", endpoint.Path, err)
	}

	nextPage := extractStartingAfter(decoded.Links.Next)
	logger.Debug().
		Str("path", endpoint.Path).
		Int("statusCode", resp.StatusCode).
		Int("resources", len(decoded.Data)).
		Str("nextPage", nextPage).
		Msg("Received Snyk API page")
	return decoded.Data, nextPage, nil
}

func extractStartingAfter(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}

	var linkString string
	if err := json.Unmarshal(raw, &linkString); err == nil {
		return startingAfterFromURL(linkString)
	}

	var linkObject struct {
		Href string `json:"href"`
	}
	if err := json.Unmarshal(raw, &linkObject); err == nil {
		return startingAfterFromURL(linkObject.Href)
	}
	return ""
}

func startingAfterFromURL(link string) string {
	if link == "" {
		return ""
	}
	parsed, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return parsed.Query().Get("starting_after")
}

func normalizeProject(resource jsonAPIResource, targetID string) projectSummary {
	return projectSummary{
		ID:              resource.ID,
		Name:            stringAttr(resource.Attributes, "name"),
		Type:            stringAttr(resource.Attributes, "type"),
		TargetReference: stringAttr(resource.Attributes, "target_reference"),
		TargetFile:      stringAttr(resource.Attributes, "target_file"),
		TargetID:        targetID,
	}
}

func renderProjectCandidates(projects []projectSummary) string {
	var buf bytes.Buffer
	table := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "PROJECT ID\tNAME\tTARGET REF\tTARGET FILE")
	for _, project := range projects {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", project.ID, display(project.Name), display(project.TargetReference), display(project.TargetFile))
	}
	table.Flush()
	return buf.String()
}

func repositoryURLCandidates(repoURL string) []string {
	seen := map[string]struct{}{}
	candidates := []string{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		candidates = append(candidates, value)
	}

	add(repoURL)

	if strings.HasPrefix(repoURL, "git@") {
		withoutPrefix := strings.TrimPrefix(repoURL, "git@")
		parts := strings.SplitN(withoutPrefix, ":", 2)
		if len(parts) == 2 {
			httpsURL := "https://" + parts[0] + "/" + parts[1]
			add(httpsURL)
			add(strings.TrimSuffix(httpsURL, ".git"))
		}
	}

	if parsed, err := url.Parse(repoURL); err == nil && parsed.Host != "" {
		httpsURL := "https://" + parsed.Host + strings.TrimSuffix(parsed.Path, ".git")
		add(httpsURL)
		add(httpsURL + ".git")
	}

	return candidates
}

func stringAttr(attrs map[string]interface{}, key string) string {
	if attrs == nil {
		return ""
	}
	value, ok := attrs[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

func display(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}
