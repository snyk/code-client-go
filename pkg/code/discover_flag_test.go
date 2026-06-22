/*
 * © 2026 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package code

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/code-client-go/internal/commands/code_workflow"
)

func TestGetCodeFlagSet_hasDiscoverSanitisers(t *testing.T) {
	flag := GetCodeFlagSet().Lookup(code_workflow.ConfigurationDiscoverSanitisers)
	require.NotNil(t, flag, "expected --%s flag on `code test`", code_workflow.ConfigurationDiscoverSanitisers)
	assert.Equal(t, "false", flag.DefValue, "--discover-sanitisers should default to false")
}
