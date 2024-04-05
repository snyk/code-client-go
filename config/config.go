package config

// Config defines the configurable options for the HTTP client.
//
//go:generate mockgen -destination=mocks/config.go -source=config.go -package mocks
type Config interface {

	// Organization is the Snyk organization in which code SAST is being run.
	// Permissions may be granted in the context of an organization. Reports
	// are also stored in the context of an owning organization.
	Organization() string

	// IsFedramp indicates whether the code SAST is being run in the context of FedRAMP.
	IsFedramp() bool

	// SnykCodeApi returns the Snyk Code API URL configured to run against, which could be
	// the one used by the Local Code Engine.
	SnykCodeApi() string

	// SnykApi returns the Snyk REST API URL configured to run against,
	SnykApi() string
}
