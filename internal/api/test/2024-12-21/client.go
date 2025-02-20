// Package v20241221 provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.4.1 DO NOT EDIT.
package v20241221

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/oapi-codegen/runtime"
	externalRef0 "github.com/snyk/code-client-go/internal/api/test/2024-12-21/common"
	externalRef1 "github.com/snyk/code-client-go/internal/api/test/2024-12-21/models"
	externalRef2 "github.com/snyk/code-client-go/internal/api/test/2024-12-21/parameters"
)

const (
	BearerAuthScopes = "bearerAuth.Scopes"
)

// CreateTestParams defines parameters for CreateTest.
type CreateTestParams struct {
	// Version The requested version of the endpoint to process the request
	Version externalRef0.Version `form:"version" json:"version"`
}

// GetTestResultParams defines parameters for GetTestResult.
type GetTestResultParams struct {
	// Version The requested version of the endpoint to process the request
	Version externalRef0.Version `form:"version" json:"version"`
}

// CreateTestApplicationVndAPIPlusJSONRequestBody defines body for CreateTest for application/vnd.api+json ContentType.
type CreateTestApplicationVndAPIPlusJSONRequestBody = externalRef1.CreateTestRequestBody

// RequestEditorFn  is the function signature for the RequestEditor callback function
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// Doer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client which conforms to the OpenAPI3 specification for this service.
type Client struct {
	// The endpoint of the server conforming to this interface, with scheme,
	// https://api.deepmap.com for example. This can contain a path relative
	// to the server, such as https://api.deepmap.com/dev-test, and all the
	// paths in the swagger spec will be appended to the server.
	Server string

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	Client HttpRequestDoer

	// A list of callbacks for modifying requests which are generated before sending over
	// the network.
	RequestEditors []RequestEditorFn
}

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// Creates a new Client, with reasonable defaults
func NewClient(server string, opts ...ClientOption) (*Client, error) {
	// create a client with sane default values
	client := Client{
		Server: server,
	}
	// mutate client and add all optional params
	for _, o := range opts {
		if err := o(&client); err != nil {
			return nil, err
		}
	}
	// ensure the server URL always has a trailing slash
	if !strings.HasSuffix(client.Server, "/") {
		client.Server += "/"
	}
	// create httpClient, if not already present
	if client.Client == nil {
		client.Client = &http.Client{}
	}
	return &client, nil
}

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HttpRequestDoer) ClientOption {
	return func(c *Client) error {
		c.Client = doer
		return nil
	}
}

// WithRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithRequestEditorFn(fn RequestEditorFn) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, fn)
		return nil
	}
}

// The interface specification for the client above.
type ClientInterface interface {
	// CreateTestWithBody request with any body
	CreateTestWithBody(ctx context.Context, orgId externalRef2.OrgId, params *CreateTestParams, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	CreateTestWithApplicationVndAPIPlusJSONBody(ctx context.Context, orgId externalRef2.OrgId, params *CreateTestParams, body CreateTestApplicationVndAPIPlusJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetTestResult request
	GetTestResult(ctx context.Context, orgId externalRef2.OrgId, testId externalRef2.TestId, params *GetTestResultParams, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) CreateTestWithBody(ctx context.Context, orgId externalRef2.OrgId, params *CreateTestParams, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	buf, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	body = bytes.NewReader(buf)
	req, err := NewCreateTestRequestWithBody(c.Server, orgId, params, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) CreateTestWithApplicationVndAPIPlusJSONBody(ctx context.Context, orgId externalRef2.OrgId, params *CreateTestParams, body CreateTestApplicationVndAPIPlusJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewCreateTestRequestWithApplicationVndAPIPlusJSONBody(c.Server, orgId, params, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetTestResult(ctx context.Context, orgId externalRef2.OrgId, testId externalRef2.TestId, params *GetTestResultParams, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetTestResultRequest(c.Server, orgId, testId, params)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewCreateTestRequestWithApplicationVndAPIPlusJSONBody calls the generic CreateTest builder with application/vnd.api+json body
func NewCreateTestRequestWithApplicationVndAPIPlusJSONBody(server string, orgId externalRef2.OrgId, params *CreateTestParams, body CreateTestApplicationVndAPIPlusJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewCreateTestRequestWithBody(server, orgId, params, "application/vnd.api+json", bodyReader)
}

// NewCreateTestRequestWithBody generates requests for CreateTest with any type of body
func NewCreateTestRequestWithBody(server string, orgId externalRef2.OrgId, params *CreateTestParams, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "org_id", runtime.ParamLocationPath, orgId)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/orgs/%s/tests", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	if params != nil {
		queryValues := queryURL.Query()

		if queryFrag, err := runtime.StyleParamWithLocation("form", true, "version", runtime.ParamLocationQuery, params.Version); err != nil {
			return nil, err
		} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
			return nil, err
		} else {
			for k, v := range parsed {
				for _, v2 := range v {
					queryValues.Add(k, v2)
				}
			}
		}

		queryURL.RawQuery = queryValues.Encode()
	}
	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewGetTestResultRequest generates requests for GetTestResult
func NewGetTestResultRequest(server string, orgId externalRef2.OrgId, testId externalRef2.TestId, params *GetTestResultParams) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "org_id", runtime.ParamLocationPath, orgId)
	if err != nil {
		return nil, err
	}

	var pathParam1 string

	pathParam1, err = runtime.StyleParamWithLocation("simple", false, "test_id", runtime.ParamLocationPath, testId)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/orgs/%s/tests/%s", pathParam0, pathParam1)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	if params != nil {
		queryValues := queryURL.Query()

		if queryFrag, err := runtime.StyleParamWithLocation("form", true, "version", runtime.ParamLocationQuery, params.Version); err != nil {
			return nil, err
		} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
			return nil, err
		} else {
			for k, v := range parsed {
				for _, v2 := range v {
					queryValues.Add(k, v2)
				}
			}
		}

		queryURL.RawQuery = queryValues.Encode()
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func (c *Client) applyEditors(ctx context.Context, req *http.Request, additionalEditors []RequestEditorFn) error {
	for _, r := range c.RequestEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	for _, r := range additionalEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// ClientWithResponses builds on ClientInterface to offer response payloads
type ClientWithResponses struct {
	ClientInterface
}

// NewClientWithResponses creates a new ClientWithResponses, which wraps
// Client with return type handling
func NewClientWithResponses(server string, opts ...ClientOption) (*ClientWithResponses, error) {
	client, err := NewClient(server, opts...)
	if err != nil {
		return nil, err
	}
	return &ClientWithResponses{client}, nil
}

// WithBaseURL overrides the baseURL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		newBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		c.Server = newBaseURL.String()
		return nil
	}
}

// ClientWithResponsesInterface is the interface specification for the client with responses above.
type ClientWithResponsesInterface interface {
	// CreateTestWithBodyWithResponse request with any body
	CreateTestWithBodyWithResponse(ctx context.Context, orgId externalRef2.OrgId, params *CreateTestParams, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*CreateTestResponse, error)

	CreateTestWithApplicationVndAPIPlusJSONBodyWithResponse(ctx context.Context, orgId externalRef2.OrgId, params *CreateTestParams, body CreateTestApplicationVndAPIPlusJSONRequestBody, reqEditors ...RequestEditorFn) (*CreateTestResponse, error)

	// GetTestResultWithResponse request
	GetTestResultWithResponse(ctx context.Context, orgId externalRef2.OrgId, testId externalRef2.TestId, params *GetTestResultParams, reqEditors ...RequestEditorFn) (*GetTestResultResponse, error)
}

type CreateTestResponse struct {
	Body                     []byte
	HTTPResponse             *http.Response
	ApplicationvndApiJSON201 *externalRef1.TestResponse
	ApplicationvndApiJSON400 *externalRef0.N400
	ApplicationvndApiJSON401 *externalRef0.N401
	ApplicationvndApiJSON403 *externalRef0.N403
	ApplicationvndApiJSON404 *externalRef0.N404
	ApplicationvndApiJSON429 *externalRef0.ErrorDocument
	ApplicationvndApiJSON500 *externalRef0.N500
}

// Status returns HTTPResponse.Status
func (r CreateTestResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r CreateTestResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetTestResultResponse struct {
	Body                     []byte
	HTTPResponse             *http.Response
	ApplicationvndApiJSON200 *externalRef1.TestResult
	ApplicationvndApiJSON400 *externalRef0.N400
	ApplicationvndApiJSON401 *externalRef0.N401
	ApplicationvndApiJSON403 *externalRef0.N403
	ApplicationvndApiJSON404 *externalRef0.N404
	ApplicationvndApiJSON429 *externalRef0.ErrorDocument
	ApplicationvndApiJSON500 *externalRef0.N500
}

// Status returns HTTPResponse.Status
func (r GetTestResultResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetTestResultResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// CreateTestWithBodyWithResponse request with arbitrary body returning *CreateTestResponse
func (c *ClientWithResponses) CreateTestWithBodyWithResponse(ctx context.Context, orgId externalRef2.OrgId, params *CreateTestParams, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*CreateTestResponse, error) {
	rsp, err := c.CreateTestWithBody(ctx, orgId, params, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseCreateTestResponse(rsp)
}

func (c *ClientWithResponses) CreateTestWithApplicationVndAPIPlusJSONBodyWithResponse(ctx context.Context, orgId externalRef2.OrgId, params *CreateTestParams, body CreateTestApplicationVndAPIPlusJSONRequestBody, reqEditors ...RequestEditorFn) (*CreateTestResponse, error) {
	rsp, err := c.CreateTestWithApplicationVndAPIPlusJSONBody(ctx, orgId, params, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseCreateTestResponse(rsp)
}

// GetTestResultWithResponse request returning *GetTestResultResponse
func (c *ClientWithResponses) GetTestResultWithResponse(ctx context.Context, orgId externalRef2.OrgId, testId externalRef2.TestId, params *GetTestResultParams, reqEditors ...RequestEditorFn) (*GetTestResultResponse, error) {
	rsp, err := c.GetTestResult(ctx, orgId, testId, params, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetTestResultResponse(rsp)
}

// ParseCreateTestResponse parses an HTTP response from a CreateTestWithResponse call
func ParseCreateTestResponse(rsp *http.Response) (*CreateTestResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &CreateTestResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 201:
		var dest externalRef1.TestResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationvndApiJSON201 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest externalRef0.N400
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationvndApiJSON400 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 401:
		var dest externalRef0.N401
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationvndApiJSON401 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 403:
		var dest externalRef0.N403
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationvndApiJSON403 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 404:
		var dest externalRef0.N404
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationvndApiJSON404 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 429:
		var dest externalRef0.ErrorDocument
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationvndApiJSON429 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest externalRef0.N500
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationvndApiJSON500 = &dest

	}

	return response, nil
}

// ParseGetTestResultResponse parses an HTTP response from a GetTestResultWithResponse call
func ParseGetTestResultResponse(rsp *http.Response) (*GetTestResultResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetTestResultResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest externalRef1.TestResult
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationvndApiJSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest externalRef0.N400
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationvndApiJSON400 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 401:
		var dest externalRef0.N401
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationvndApiJSON401 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 403:
		var dest externalRef0.N403
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationvndApiJSON403 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 404:
		var dest externalRef0.N404
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationvndApiJSON404 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 429:
		var dest externalRef0.ErrorDocument
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationvndApiJSON429 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest externalRef0.N500
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationvndApiJSON500 = &dest

	}

	return response, nil
}
