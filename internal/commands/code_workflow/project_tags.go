package code_workflow

import (
	"fmt"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

const missingProjectTagsValue = "__snyk_missing_project_tags_value__"

func MissingProjectTagsValue() string {
	return missingProjectTagsValue
}

func GenerateProjectLabels(config configuration.Configuration) (map[string]string, error) {
	if !config.IsSet(ConfigurationProjectTags) {
		return nil, nil
	}

	rawTags := config.GetString(ConfigurationProjectTags)

	if rawTags == "" {
		return map[string]string{}, nil
	}

	if rawTags == missingProjectTagsValue {
		return nil, fmt.Errorf(`--project-tags must contain an '=' with a comma-separated list of pairs (also separated with an '='). To clear all existing values, pass no values i.e. --project-tags=`)
	}

	keyEqualsValuePairs := strings.Split(rawTags, ",")
	labels := make(map[string]string, len(keyEqualsValuePairs))
	for _, keyEqualsValue := range keyEqualsValuePairs {
		parts := strings.SplitN(keyEqualsValue, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf(`The tag "%s" does not have an "=" separating the key and value. For example: --project-tags=KEY=VALUE`, keyEqualsValue)
		}
		if parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf(`The tag "%s" must contain a non-empty key and value. For example: --project-tags=KEY=VALUE`, keyEqualsValue)
		}

		labels[parts[0]] = parts[1]
	}

	return labels, nil
}
