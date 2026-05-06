package code_workflow

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
)

func TestGenerateProjectTags(t *testing.T) {
	t.Run("returns nil when project tags are not set", func(t *testing.T) {
		config := configuration.NewWithOpts()

		tags, err := GenerateProjectTags(config)

		assert.NoError(t, err)
		assert.Nil(t, tags)
	})

	t.Run("returns empty project tags when project tags are cleared", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationProjectTags, "")

		tags, err := GenerateProjectTags(config)

		assert.NoError(t, err)
		assert.NotNil(t, tags)
		assert.Empty(t, *tags)
	})

	t.Run("parses project tags", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationProjectTags, "env=prod,team=security")

		tags, err := GenerateProjectTags(config)

		assert.NoError(t, err)
		assert.NotNil(t, tags)
		assert.Equal(t, []string{"env=prod", "team=security"}, *tags)
	})

	t.Run("errors when a tag is missing an equals sign", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationProjectTags, "env")

		tags, err := GenerateProjectTags(config)

		assert.Nil(t, tags)
		assert.EqualError(t, err, `The tag "env" does not have an "=" separating the key and value. For example: --project-tags=KEY=VALUE`)
	})

	t.Run("errors when a tag has an empty key or value", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationProjectTags, "env=")

		tags, err := GenerateProjectTags(config)

		assert.Nil(t, tags)
		assert.EqualError(t, err, `The tag "env=" must contain a non-empty key and value. For example: --project-tags=KEY=VALUE`)
	})

	t.Run("preserves duplicate keys", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationProjectTags, "team=alpha,team=beta")

		tags, err := GenerateProjectTags(config)

		assert.NoError(t, err)
		assert.NotNil(t, tags)
		assert.Equal(t, []string{"team=alpha", "team=beta"}, *tags)
	})
}
