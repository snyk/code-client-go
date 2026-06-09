package code_workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strconv"
	"text/tabwriter"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ConfigurationIgnored = "ignored"
	ConfigurationLimit   = "limit"
	ConfigurationAll     = "all"

	defaultIssuesLimit = 100
)

type codeIssuesOptions struct {
	Org             string
	InputPath       string
	ProjectID       string
	RemoteRepoURL   string
	TargetReference string
	Ignored         string
	Severity        string
	Limit           int
	FetchAll        bool
	JSON            bool
}

type codeIssuesOutput struct {
	Project        *projectSummary `json:"project,omitempty"`
	ResolvedFrom   *resolvedFrom   `json:"resolvedFrom,omitempty"`
	IgnoredFilter  string          `json:"ignoredFilter"`
	SeverityFilter string          `json:"severityFilter,omitempty"`
	Issues         []codeIssue     `json:"issues"`
	IssueCount     int             `json:"issueCount"`
	Complete       bool            `json:"complete"`
	NextPage       string          `json:"nextPage,omitempty"`
	APIURL         string          `json:"apiUrl"`
	APIVersion     string          `json:"apiVersion"`
}

type codeIssue struct {
	ID        string          `json:"id"`
	Type      string          `json:"type,omitempty"`
	Title     string          `json:"title,omitempty"`
	Severity  string          `json:"severity,omitempty"`
	Status    string          `json:"status,omitempty"`
	Ignored   *bool           `json:"ignored,omitempty"`
	ProjectID string          `json:"projectId,omitempty"`
	Location  string          `json:"location,omitempty"`
	Raw       jsonAPIResource `json:"raw"`
}

func EntryPointIssues(invocationCtx workflow.InvocationContext) ([]workflow.Data, error) {
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()

	options, err := getCodeIssuesOptions(config)
	if err != nil {
		return nil, err
	}

	client := newCodeProjectResolverClient(config.GetString(configuration.API_URL), invocationCtx.GetNetworkAccess().GetHttpClient())
	output, err := listCodeIssues(invocationCtx.Context(), client, options, logger)
	if err != nil {
		return nil, err
	}

	var payload interface{}
	contentType := "text/plain"
	if options.JSON {
		payload, err = json.MarshalIndent(output, "", "  ")
		if err != nil {
			return nil, err
		}
		contentType = "application/json"
	} else {
		payload = renderCodeIssuesTable(output)
	}

	return []workflow.Data{
		workflow.NewData(
			workflow.NewTypeIdentifier(invocationCtx.GetWorkflowIdentifier(), "issues"),
			contentType,
			payload,
			workflow.WithConfiguration(config),
			workflow.WithLogger(logger),
		),
	}, nil
}

func getCodeIssuesOptions(config configuration.Configuration) (codeIssuesOptions, error) {
	options := codeIssuesOptions{
		Org:             config.GetString(configuration.ORGANIZATION),
		InputPath:       config.GetString(configuration.INPUT_DIRECTORY),
		ProjectID:       config.GetString(ConfigurationProjectId),
		RemoteRepoURL:   config.GetString(configuration.FLAG_REMOTE_REPO_URL),
		TargetReference: config.GetString(ConfigurationTargetReference),
		Ignored:         config.GetString(ConfigurationIgnored),
		Severity:        config.GetString(configuration.FLAG_SEVERITY_THRESHOLD),
		Limit:           config.GetInt(ConfigurationLimit),
		FetchAll:        config.GetBool(ConfigurationAll),
		JSON:            config.GetBool("json"),
	}

	if options.Org == "" {
		return options, errors.New("org must be provided")
	}

	if options.InputPath == "" {
		options.InputPath = "."
	}

	if options.ProjectID != "" {
		if _, err := uuid.Parse(options.ProjectID); err != nil {
			return options, fmt.Errorf("\"project-id\" must be a valid UUID: %w", err)
		}
	}

	switch options.Ignored {
	case "", "false":
		options.Ignored = "false"
	case "true", "all":
	default:
		return options, fmt.Errorf("invalid ignored value %q, expected true, false, or all", options.Ignored)
	}

	if options.Limit == 0 {
		options.Limit = defaultIssuesLimit
	}
	if options.Limit < 10 || options.Limit > 100 {
		return options, fmt.Errorf("limit must be between 10 and 100")
	}

	if options.Severity != "" && !isValidSeverity(options.Severity) {
		return options, fmt.Errorf("invalid severity-threshold %q, expected low, medium, high, or critical", options.Severity)
	}

	return options, nil
}

func listCodeIssues(ctx context.Context, client *codeProjectResolverClient, options codeIssuesOptions, logger *zerolog.Logger) (codeIssuesOutput, error) {
	logger.Debug().
		Str("org", options.Org).
		Str("inputPath", options.InputPath).
		Str("projectID", options.ProjectID).
		Str("remoteRepoURL", options.RemoteRepoURL).
		Str("targetReference", options.TargetReference).
		Str("ignored", options.Ignored).
		Str("severityThreshold", options.Severity).
		Int("limit", options.Limit).
		Bool("all", options.FetchAll).
		Msg("Listing Snyk Code issues")

	project, resolved, err := resolveCodeProject(ctx, client, codeProjectResolutionOptions{
		Org:             options.Org,
		InputPath:       options.InputPath,
		ProjectID:       options.ProjectID,
		RemoteRepoURL:   options.RemoteRepoURL,
		TargetReference: options.TargetReference,
		Limit:           options.Limit,
		FetchAll:        options.FetchAll,
	}, logger)
	if err != nil {
		return codeIssuesOutput{}, err
	}

	issues, complete, nextPage, err := client.listIssues(ctx, options.Org, project.ID, options.Ignored, options.Limit, options.FetchAll, logger)
	if err != nil {
		return codeIssuesOutput{}, err
	}

	normalizedIssues := make([]codeIssue, 0, len(issues))
	for _, issue := range issues {
		normalizedIssue := normalizeIssue(issue, project.ID)
		if severityAtLeast(normalizedIssue.Severity, options.Severity) {
			normalizedIssues = append(normalizedIssues, normalizedIssue)
		}
	}
	sort.SliceStable(normalizedIssues, func(i, j int) bool {
		return severityRank(normalizedIssues[i].Severity) > severityRank(normalizedIssues[j].Severity)
	})

	logger.Debug().Msgf("Resolved %d code issues for project %s", len(normalizedIssues), project.ID)

	return codeIssuesOutput{
		Project:        &project,
		ResolvedFrom:   resolved,
		IgnoredFilter:  options.Ignored,
		SeverityFilter: options.Severity,
		Issues:         normalizedIssues,
		IssueCount:     len(normalizedIssues),
		Complete:       complete,
		NextPage:       nextPage,
		APIURL:         client.apiURL,
		APIVersion:     codeProjectResolverAPIVersion,
	}, nil
}

func (c *codeProjectResolverClient) listIssues(ctx context.Context, org string, projectID string, ignored string, limit int, fetchAll bool, logger *zerolog.Logger) ([]jsonAPIResource, bool, string, error) {
	params := url.Values{}
	params.Set("version", codeProjectResolverAPIVersion)
	params.Set("scan_item.id", projectID)
	params.Set("scan_item.type", "project")
	params.Set("type", "code")
	params.Set("limit", strconv.Itoa(limit))
	if ignored != "all" {
		params.Set("ignored", ignored)
	}

	resources, nextPage, err := c.getPage(ctx, path.Join("rest", "orgs", org, "issues"), params, logger)
	if err != nil {
		return nil, false, "", err
	}
	if !fetchAll || nextPage == "" {
		return resources, nextPage == "", nextPage, nil
	}

	allResources := append([]jsonAPIResource{}, resources...)
	for nextPage != "" {
		params.Set("starting_after", nextPage)
		resources, nextPage, err = c.getPage(ctx, path.Join("rest", "orgs", org, "issues"), params, logger)
		if err != nil {
			return allResources, false, nextPage, err
		}
		allResources = append(allResources, resources...)
	}
	return allResources, true, "", nil
}

func normalizeIssue(resource jsonAPIResource, projectID string) codeIssue {
	return codeIssue{
		ID:        resource.ID,
		Type:      resource.Type,
		Title:     firstStringAttr(resource.Attributes, "title", "name", "message", "rule", "key"),
		Severity:  firstStringAttr(resource.Attributes, "effective_severity_level", "severity", "severity_level"),
		Status:    firstStringAttr(resource.Attributes, "status", "state"),
		Ignored:   boolAttr(resource.Attributes, "ignored"),
		ProjectID: projectID,
		Location:  issueLocation(resource.Attributes),
		Raw:       resource,
	}
}

func renderCodeIssuesTable(output codeIssuesOutput) string {
	var buf bytes.Buffer
	if output.Project != nil {
		fmt.Fprintf(&buf, "Project: %s", output.Project.ID)
		if output.Project.Name != "" {
			fmt.Fprintf(&buf, " (%s)", output.Project.Name)
		}
		buf.WriteByte('\n')
	}
	if output.ResolvedFrom != nil {
		fmt.Fprintf(&buf, "Resolved from: %s @ %s\n", output.ResolvedFrom.RemoteRepoURL, output.ResolvedFrom.TargetReference)
	}
	fmt.Fprintf(&buf, "Issues: %d", output.IssueCount)
	if !output.Complete {
		fmt.Fprintf(&buf, " (more results available; use --all to fetch all pages)")
	}
	buf.WriteString("\n\n")

	if len(output.Issues) == 0 {
		buf.WriteString("No Snyk Code issues found.\n")
		return buf.String()
	}

	table := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "SEVERITY\tTITLE\tLOCATION\tIGNORED\tISSUE ID")
	for _, issue := range output.Issues {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n",
			display(issue.Severity),
			display(issue.Title),
			display(issue.Location),
			displayBool(issue.Ignored),
			issue.ID,
		)
	}
	table.Flush()
	return buf.String()
}

func issueLocation(attrs map[string]interface{}) string {
	for _, key := range []string{"location", "file_path", "path", "primary_file_path"} {
		if value := stringAttr(attrs, key); value != "" {
			return value
		}
	}
	if value := sourceLocationFromCoordinates(attrs); value != "" {
		return value
	}
	return ""
}

func sourceLocationFromCoordinates(attrs map[string]interface{}) string {
	coordinates, ok := attrs["coordinates"].([]interface{})
	if !ok {
		return ""
	}
	for _, coordinate := range coordinates {
		coordinateMap, ok := coordinate.(map[string]interface{})
		if !ok {
			continue
		}
		representations, ok := coordinateMap["representations"].([]interface{})
		if !ok {
			continue
		}
		for _, representation := range representations {
			representationMap, ok := representation.(map[string]interface{})
			if !ok {
				continue
			}
			sourceLocation, ok := representationMap["sourceLocation"].(map[string]interface{})
			if !ok {
				continue
			}
			file := stringAttr(sourceLocation, "file")
			if file == "" {
				continue
			}
			line := sourceLocationStartLine(sourceLocation)
			if line > 0 {
				return fmt.Sprintf("%s:%d", file, line)
			}
			return file
		}
	}
	return ""
}

func sourceLocationStartLine(sourceLocation map[string]interface{}) int {
	region, ok := sourceLocation["region"].(map[string]interface{})
	if !ok {
		return 0
	}
	start, ok := region["start"].(map[string]interface{})
	if !ok {
		return 0
	}
	switch line := start["line"].(type) {
	case int:
		return line
	case float64:
		return int(line)
	case json.Number:
		value, _ := line.Int64()
		return int(value)
	default:
		return 0
	}
}

func firstStringAttr(attrs map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value := stringAttr(attrs, key); value != "" {
			return value
		}
	}
	return ""
}

func boolAttr(attrs map[string]interface{}, key string) *bool {
	if attrs == nil {
		return nil
	}
	value, ok := attrs[key]
	if !ok {
		return nil
	}
	if typed, ok := value.(bool); ok {
		return &typed
	}
	return nil
}

func displayBool(value *bool) string {
	if value == nil {
		return "-"
	}
	if *value {
		return "true"
	}
	return "false"
}

func isValidSeverity(severity string) bool {
	switch severity {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func severityAtLeast(severity string, threshold string) bool {
	if threshold == "" {
		return true
	}
	return severityRank(severity) >= severityRank(threshold)
}

func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
