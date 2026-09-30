package contributorbilling

import (
	"context"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/contributorbilling"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func defaultRepoPath(repoPath string) string {
	if strings.TrimSpace(repoPath) == "" {
		return "."
	}
	return repoPath
}

func authHeader(config configuration.Configuration) string {
	if token := strings.TrimSpace(config.GetString(configuration.AUTHENTICATION_TOKEN)); token != "" {
		return "token " + token
	}
	if bearer := strings.TrimSpace(config.GetString(configuration.AUTHENTICATION_BEARER_TOKEN)); bearer != "" {
		return "Bearer " + bearer
	}
	return ""
}

// EmitProject fires contributor billing after a successful native code report test.
// It is fire-and-forget and must not affect command exit codes.
func EmitProject(
	ctx context.Context,
	ictx workflow.InvocationContext,
	projectID string,
	repoPath string,
) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" || ictx == nil {
		return
	}

	config := ictx.GetConfiguration()
	scopeID := strings.TrimSpace(config.GetString(configuration.ORGANIZATION))
	if scopeID == "" {
		return
	}

	contributorbilling.EmitContributorBilling(ctx, contributorbilling.EmitOptions{
		HTTPClient:          ictx.GetNetworkAccess().GetHttpClient(),
		IngestURL:           config.GetString(configuration.API_URL),
		AuthHeader:          authHeader(config),
		Capability:          contributorbilling.CapabilityCode,
		ScopeID:             scopeID,
		RepoPath:            defaultRepoPath(repoPath),
		CollectContributors: true,
		Timeout:             contributorbilling.DefaultTimeout,
		Logger:              ictx.GetEnhancedLogger(),
		Items: []contributorbilling.BillingItem{
			{EntityID: projectID},
		},
	})
}
