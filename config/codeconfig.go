package config

import "time"

// CodeConfig provides a concrete implementation of the Config interface
type CodeConfig struct {
	organization string
	snykCodeApi  string
	snykApi      string
	isFedramp    bool
	timeout      time.Duration
}

// NewCodeConfig creates a new code config implementation
func NewCodeConfig(organization, snykCodeApi, snykApi string, isFedramp bool, timeout time.Duration) *CodeConfig {
	return &CodeConfig{
		organization: organization,
		snykCodeApi:  snykCodeApi,
		snykApi:      snykApi,
		isFedramp:    isFedramp,
		timeout:      timeout,
	}
}

func (c *CodeConfig) Organization() string {
	return c.organization
}

func (c *CodeConfig) IsFedramp() bool {
	return c.isFedramp
}

func (c *CodeConfig) SnykCodeApi() string {
	return c.snykCodeApi
}

func (c *CodeConfig) SnykApi() string {
	return c.snykApi
}

func (c *CodeConfig) SnykCodeAnalysisTimeout() time.Duration {
	return c.timeout
}
