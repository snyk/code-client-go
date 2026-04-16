package code_workflow

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
)

func TestGenerateProjectLabels(t *testing.T) {
	t.Run("returns nil when project tags are not set", func(t *testing.T) {
		config := configuration.NewWithOpts()

		labels, err := GenerateProjectLabels(config)

		assert.NoError(t, err)
		assert.Nil(t, labels)
	})

	t.Run("returns empty labels when project tags are cleared", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationProjectTags, "")

		labels, err := GenerateProjectLabels(config)

		assert.NoError(t, err)
		assert.NotNil(t, labels)
		assert.Empty(t, labels)
	})

	t.Run("parses project tags into labels", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationProjectTags, "env=prod,team=security")

		labels, err := GenerateProjectLabels(config)

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{
			"env":  "prod",
			"team": "security",
		}, labels)
	})

	t.Run("errors when project-tags is passed without a value", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationProjectTags, MissingProjectTagsValue())

		labels, err := GenerateProjectLabels(config)

		assert.Nil(t, labels)
		assert.EqualError(t, err, `--project-tags must contain an '=' with a comma-separated list of pairs (also separated with an '='). To clear all existing values, pass no values i.e. --project-tags=`)
	})

	t.Run("errors when a tag is missing an equals sign", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationProjectTags, "env")

		labels, err := GenerateProjectLabels(config)

		assert.Nil(t, labels)
		assert.EqualError(t, err, `The tag "env" does not have an "=" separating the key and value. For example: --project-tags=KEY=VALUE`)
	})

	t.Run("errors when a tag has an empty key or value", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationProjectTags, "env=")

		labels, err := GenerateProjectLabels(config)

		assert.Nil(t, labels)
		assert.EqualError(t, err, `The tag "env=" must contain a non-empty key and value. For example: --project-tags=KEY=VALUE`)
	})

	t.Run("last value wins for duplicate keys", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationProjectTags, "team=alpha,team=beta")

		labels, err := GenerateProjectLabels(config)

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"team": "beta"}, labels)
	})
}
