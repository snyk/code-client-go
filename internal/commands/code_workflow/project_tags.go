package code_workflow

import (
	"fmt"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func GenerateProjectTags(config configuration.Configuration) (*[]string, error) {
	if !config.IsSet(ConfigurationProjectTags) {
		return nil, nil
	}

	rawTags := config.GetString(ConfigurationProjectTags)

	if rawTags == "" {
		tags := []string{}
		return &tags, nil
	}

	keyEqualsValuePairs := strings.Split(rawTags, ",")
	tags := make([]string, 0, len(keyEqualsValuePairs))
	for _, keyEqualsValue := range keyEqualsValuePairs {
		parts := strings.SplitN(keyEqualsValue, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf(`The tag "%s" does not have an "=" separating the key and value. For example: --project-tags=KEY=VALUE`, keyEqualsValue)
		}
		if parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf(`The tag "%s" must contain a non-empty key and value. For example: --project-tags=KEY=VALUE`, keyEqualsValue)
		}

		tags = append(tags, keyEqualsValue)
	}

	return &tags, nil
}
