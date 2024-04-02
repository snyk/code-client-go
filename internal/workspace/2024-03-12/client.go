// Package v20240312 provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.13.4 DO NOT EDIT.
package v20240312

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/deepmap/oapi-codegen/pkg/runtime"
	externalRef0 "github.com/snyk/code-client-go/internal/workspace/2024-03-12/common"
	externalRef2 "github.com/snyk/code-client-go/internal/workspace/2024-03-12/parameters"
	externalRef3 "github.com/snyk/code-client-go/internal/workspace/2024-03-12/workspaces"
)

const (
	BearerAuthScopes = "bearerAuth.Scopes"
)

// Defines values for CreateWorkspaceParamsContentType.
const (
	ApplicationvndApiJson CreateWorkspaceParamsContentType = "application/vnd.api+json"
)

// CreateWorkspaceParams defines parameters for CreateWorkspace.
type CreateWorkspaceParams struct {
	// Version The requested version of the endpoint to process the request
	Version externalRef0.Version `form:"version" json:"version"`

	// SnykRequestId Request ID
	SnykRequestId externalRef2.RequestId `json:"snyk-request-id"`

	// UserAgent The client that sent the request, as per RFC 7231.
	UserAgent externalRef2.UserAgent `json:"user-agent"`

	// ContentType Content type header
	ContentType CreateWorkspaceParamsContentType `json:"content-type"`
}

// CreateWorkspaceParamsContentType defines parameters for CreateWorkspace.
type CreateWorkspaceParamsContentType string

// CreateWorkspaceApplicationVndAPIPlusJSONRequestBody defines body for CreateWorkspace for application/vnd.api+json ContentType.
type CreateWorkspaceApplicationVndAPIPlusJSONRequestBody = externalRef3.WorkspacePostRequest

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
	// CreateWorkspaceWithBody request with any body
	CreateWorkspaceWithBody(ctx context.Context, orgId externalRef2.OrgId, params *CreateWorkspaceParams, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	CreateWorkspaceWithApplicationVndAPIPlusJSONBody(ctx context.Context, orgId externalRef2.OrgId, params *CreateWorkspaceParams, body CreateWorkspaceApplicationVndAPIPlusJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) CreateWorkspaceWithBody(ctx context.Context, orgId externalRef2.OrgId, params *CreateWorkspaceParams, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewCreateWorkspaceRequestWithBody(c.Server, orgId, params, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) CreateWorkspaceWithApplicationVndAPIPlusJSONBody(ctx context.Context, orgId externalRef2.OrgId, params *CreateWorkspaceParams, body CreateWorkspaceApplicationVndAPIPlusJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewCreateWorkspaceRequestWithApplicationVndAPIPlusJSONBody(c.Server, orgId, params, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewCreateWorkspaceRequestWithApplicationVndAPIPlusJSONBody calls the generic CreateWorkspace builder with application/vnd.api+json body
func NewCreateWorkspaceRequestWithApplicationVndAPIPlusJSONBody(server string, orgId externalRef2.OrgId, params *CreateWorkspaceParams, body CreateWorkspaceApplicationVndAPIPlusJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewCreateWorkspaceRequestWithBody(server, orgId, params, "application/vnd.api+json", bodyReader)
}

// NewCreateWorkspaceRequestWithBody generates requests for CreateWorkspace with any type of body
func NewCreateWorkspaceRequestWithBody(server string, orgId externalRef2.OrgId, params *CreateWorkspaceParams, contentType string, body io.Reader) (*http.Request, error) {
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

	operationPath := fmt.Sprintf("/orgs/%s/workspaces", pathParam0)
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

	if params != nil {

		var headerParam0 string

		headerParam0, err = runtime.StyleParamWithLocation("simple", false, "snyk-request-id", runtime.ParamLocationHeader, params.SnykRequestId)
		if err != nil {
			return nil, err
		}

		req.Header.Set("snyk-request-id", headerParam0)

		var headerParam1 string

		headerParam1, err = runtime.StyleParamWithLocation("simple", false, "user-agent", runtime.ParamLocationHeader, params.UserAgent)
		if err != nil {
			return nil, err
		}

		req.Header.Set("user-agent", headerParam1)

		var headerParam2 string

		headerParam2, err = runtime.StyleParamWithLocation("simple", false, "content-type", runtime.ParamLocationHeader, params.ContentType)
		if err != nil {
			return nil, err
		}

		req.Header.Set("content-type", headerParam2)

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
	// CreateWorkspaceWithBodyWithResponse request with any body
	CreateWorkspaceWithBodyWithResponse(ctx context.Context, orgId externalRef2.OrgId, params *CreateWorkspaceParams, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*CreateWorkspaceResponse, error)

	CreateWorkspaceWithApplicationVndAPIPlusJSONBodyWithResponse(ctx context.Context, orgId externalRef2.OrgId, params *CreateWorkspaceParams, body CreateWorkspaceApplicationVndAPIPlusJSONRequestBody, reqEditors ...RequestEditorFn) (*CreateWorkspaceResponse, error)
}

type CreateWorkspaceResponse struct {
	Body                     []byte
	HTTPResponse             *http.Response
	ApplicationvndApiJSON201 *externalRef3.WorkspacePostResponse
	ApplicationvndApiJSON400 *externalRef0.N400
	ApplicationvndApiJSON401 *externalRef0.N401
	ApplicationvndApiJSON403 *externalRef0.N403
	ApplicationvndApiJSON500 *externalRef0.N500
}

// Status returns HTTPResponse.Status
func (r CreateWorkspaceResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r CreateWorkspaceResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// CreateWorkspaceWithBodyWithResponse request with arbitrary body returning *CreateWorkspaceResponse
func (c *ClientWithResponses) CreateWorkspaceWithBodyWithResponse(ctx context.Context, orgId externalRef2.OrgId, params *CreateWorkspaceParams, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*CreateWorkspaceResponse, error) {
	rsp, err := c.CreateWorkspaceWithBody(ctx, orgId, params, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseCreateWorkspaceResponse(rsp)
}

func (c *ClientWithResponses) CreateWorkspaceWithApplicationVndAPIPlusJSONBodyWithResponse(ctx context.Context, orgId externalRef2.OrgId, params *CreateWorkspaceParams, body CreateWorkspaceApplicationVndAPIPlusJSONRequestBody, reqEditors ...RequestEditorFn) (*CreateWorkspaceResponse, error) {
	rsp, err := c.CreateWorkspaceWithApplicationVndAPIPlusJSONBody(ctx, orgId, params, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseCreateWorkspaceResponse(rsp)
}

// ParseCreateWorkspaceResponse parses an HTTP response from a CreateWorkspaceWithResponse call
func ParseCreateWorkspaceResponse(rsp *http.Response) (*CreateWorkspaceResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &CreateWorkspaceResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 201:
		var dest externalRef3.WorkspacePostResponse
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

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest externalRef0.N500
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationvndApiJSON500 = &dest

	}

	return response, nil
}
