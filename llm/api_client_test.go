package llm

import (
	"encoding/json"
	"net/http"
	"testing"

	http2 "github.com/snyk/code-client-go/http"
	"github.com/stretchr/testify/assert"
)

// Test with existing headers
func TestAddDefaultHeadersWithExistingHeaders(t *testing.T) {
	req := &http.Request{Header: http.Header{"Existing-Header": {"existing-value"}}}

	http2.AddDefaultHeaders(req, http2.NoRequestId, "", http.MethodPost, true)

	cacheControl := req.Header.Get("Cache-Control")
	contentType := req.Header.Get("Content-Type")
	existingHeader := req.Header.Get("Existing-Header")

	if cacheControl != "private, max-age=0, no-cache" {
		t.Errorf("Expected Cache-Control header to be 'private, max-age=0, no-cache', got %s", cacheControl)
	}

	if contentType != "application/octet-stream" {
		t.Errorf("Expected Content-Type header to be 'application/json', got %s", contentType)
	}

	if existingHeader != "existing-value" {
		t.Errorf("Expected Existing-Header to be 'existing-value', got %s", existingHeader)
	}
}

// Test with existing headers
func TestAddDefaultHeadersWithSkipEncodingEnabled(t *testing.T) {
	req := &http.Request{Header: http.Header{"Existing-Header": {"existing-value"}}}

	http2.AddDefaultHeaders(req, http2.NoRequestId, "", http.MethodPost, false)

	cacheControl := req.Header.Get("Cache-Control")
	contentType := req.Header.Get("Content-Type")
	existingHeader := req.Header.Get("Existing-Header")

	if cacheControl != "private, max-age=0, no-cache" {
		t.Errorf("Expected Cache-Control header to be 'private, max-age=0, no-cache', got %s", cacheControl)
	}

	if contentType != "application/json" {
		t.Errorf("Expected Content-Type header to be 'application/json', got %s", contentType)
	}

	if existingHeader != "existing-value" {
		t.Errorf("Expected Existing-Header to be 'existing-value', got %s", existingHeader)
	}
}

func TestAutofixRequestBody(t *testing.T) {
	d := &DeepCodeLLMBindingImpl{}

	const testBundleHash = "0123456789abcdef"
	const testBaseDir = "basedir"
	const testFilePath = "/path/to/file"
	const testLineNumber0Based = 0
	const testRuleId = "rule_id"
	const testShardKey = "shard_key"
	const testHost = "http://api.test.snyk.io"
	const testIdeName = "my IDE"
	const testIdeVersion = "1.0.0"
	const testExtensionName = "my extension"
	const testExtensionVersion = "1.2.3"

	options := AutofixOptions{
		RuleID:     testRuleId,
		BundleHash: testBundleHash,
		ShardKey:   testShardKey,
		Host:       testHost,
		BaseDir:    testBaseDir,
		FilePath:   testFilePath,
		LineNum:    testLineNumber0Based,
		CodeRequestContext: CodeRequestContext{
			Initiator: "",
			Flow:      "",
			Org:       CodeRequestContextOrg{},
		},
		IdeExtensionDetails: AutofixIdeExtensionDetails{
			IdeName:          testIdeName,
			IdeVersion:       testIdeVersion,
			ExtensionName:    testExtensionName,
			ExtensionVersion: testExtensionVersion,
		},
	}

	jsonBody, err := d.autofixRequestBody(&options)
	assert.NoError(t, err)

	expectedBody := AutofixRequest{
		Key: AutofixRequestKey{
			Type:     "file",
			Hash:     testBundleHash,
			Shard:    testShardKey,
			FilePath: testFilePath,
			RuleId:   testRuleId,
			LineNum:  testLineNumber0Based,
		},
		AnalysisContext: CodeRequestContext{
			Initiator: "",
			Flow:      "",
			Org:       CodeRequestContextOrg{},
		},
		IdeExtensionDetails: AutofixIdeExtensionDetails{
			IdeName:          testIdeName,
			IdeVersion:       testIdeVersion,
			ExtensionName:    testExtensionName,
			ExtensionVersion: testExtensionVersion,
		},
	}

	var body AutofixRequest
	err = json.Unmarshal(jsonBody, &body)
	assert.NoError(t, err)

	assert.Equal(t, expectedBody, body)
}
