package llm

import (
	"bytes"
	"io"
	"net/http"

	httpclient "github.com/snyk/code-client-go/http"
)

// MockHTTPResponse represents a predefined response for the mock HTTP client
type MockHTTPResponse struct {
	// Body is the response body
	Body []byte
	// StatusCode is the HTTP status code
	StatusCode int
	// Error is the error to return (if any)
	Error error
}

// MockHTTPClient implements the httpclient.HTTPClient interface
// to enable mocking of HTTP requests in tests
type MockHTTPClient struct {
	// Response is returned when no matching path is found
	Response MockHTTPResponse
	// ReceivedRequests stores the requests that were made
	ReceivedRequests []*http.Request
}

// NewMockHTTPClient creates a new MockHTTPClient with a default response
func NewMockHTTPClient() *MockHTTPClient {
	return &MockHTTPClient{}
}

// WithMockHTTP is an option function that configures a DeepCodeLLMBindingImpl
// to use a mock HTTP client
func WithMockHTTP(mockHTTP *MockHTTPClient) Option {
	return func(d *DeepCodeLLMBindingImpl) {
		d.httpClientFunc = func() httpclient.HTTPClient {
			return mockHTTP
		}
	}
}

// Do implements the httpclient.HTTPClient interface with the mock implementation
func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	// Store the request for later inspection
	m.ReceivedRequests = append(m.ReceivedRequests, req)

	response := m.Response

	// Return an error if configured
	if response.Error != nil {
		return nil, response.Error
	}

	// Create the HTTP response
	statusCode := http.StatusOK
	if response.StatusCode != 0 {
		statusCode = response.StatusCode
	}

	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewReader(response.Body)),
	}, nil
}

// GetLastRequest returns the most recent HTTP request made
func (m *MockHTTPClient) GetLastRequest() *http.Request {
	if len(m.ReceivedRequests) == 0 {
		return nil
	}
	return m.ReceivedRequests[len(m.ReceivedRequests)-1]
}
