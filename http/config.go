package http

// Config defines the configurable options for the HTTP client.
type Config interface {

	// Organization is the Snyk organization in which code SAST is being run.
	// Permissions may be granted in the context of an organization. Reports
	// are also stored in the context of an owning organization.
	Organization() string

	// IsFedramp indicates whether the code SAST is being run in the context of FedRAMP.
	IsFedramp() bool
}
