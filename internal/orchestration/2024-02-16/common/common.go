// Package v20240216 provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.16.3 DO NOT EDIT.
package v20240216

import (
	"encoding/json"

	"github.com/oapi-codegen/runtime"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

// Defines values for MetaCount.
const (
	Only MetaCount = "only"
	With MetaCount = "with"
)

// ActualVersion Resolved API version
type ActualVersion = string

// Error defines model for Error.
type Error struct {
	// Code An application-specific error code, expressed as a string value.
	Code *string `json:"code,omitempty"`

	// Detail A human-readable explanation specific to this occurrence of the problem.
	Detail string `json:"detail"`

	// Id A unique identifier for this particular occurrence of the problem.
	Id *openapi_types.UUID `json:"id,omitempty"`

	// Links A link that leads to further details about this particular occurrance of the problem.
	Links  *ErrorLink              `json:"links,omitempty"`
	Meta   *map[string]interface{} `json:"meta,omitempty"`
	Source *struct {
		// Parameter A string indicating which URI query parameter caused the error.
		Parameter *string `json:"parameter,omitempty"`

		// Pointer A JSON Pointer [RFC6901] to the associated entity in the request document.
		Pointer *string `json:"pointer,omitempty"`
	} `json:"source,omitempty"`

	// Status The HTTP status code applicable to this problem, expressed as a string value.
	Status string `json:"status"`

	// Title A short, human-readable summary of the problem that SHOULD NOT change from occurrence to occurrence of the problem, except for purposes of localization.
	Title *string `json:"title,omitempty"`
}

// ErrorDocument defines model for ErrorDocument.
type ErrorDocument struct {
	Errors  []Error `json:"errors"`
	Jsonapi JsonApi `json:"jsonapi"`
}

// ErrorLink A link that leads to further details about this particular occurrance of the problem.
type ErrorLink struct {
	About *LinkProperty `json:"about,omitempty"`
}

// JsonApi defines model for JsonApi.
type JsonApi struct {
	// Version Version of the JSON API specification this server supports.
	Version string `json:"version"`
}

// LinkProperty defines model for LinkProperty.
type LinkProperty struct {
	union json.RawMessage
}

// LinkProperty0 A string containing the link’s URL.
type LinkProperty0 = string

// LinkProperty1 defines model for .
type LinkProperty1 struct {
	// Href A string containing the link’s URL.
	Href string `json:"href"`

	// Meta Free-form object that may contain non-standard information.
	Meta *Meta `json:"meta,omitempty"`
}

// Links defines model for Links.
type Links struct {
	First   *LinkProperty `json:"first,omitempty"`
	Last    *LinkProperty `json:"last,omitempty"`
	Next    *LinkProperty `json:"next,omitempty"`
	Prev    *LinkProperty `json:"prev,omitempty"`
	Related *LinkProperty `json:"related,omitempty"`
	Self    *LinkProperty `json:"self,omitempty"`
}

// Meta Free-form object that may contain non-standard information.
type Meta map[string]interface{}

// PaginatedLinks defines model for PaginatedLinks.
type PaginatedLinks struct {
	First *LinkProperty `json:"first,omitempty"`
	Last  *LinkProperty `json:"last,omitempty"`
	Next  *LinkProperty `json:"next,omitempty"`
	Prev  *LinkProperty `json:"prev,omitempty"`
	Self  *LinkProperty `json:"self,omitempty"`
}

// QueryVersion Requested API version
type QueryVersion = string

// RelatedLink defines model for RelatedLink.
type RelatedLink struct {
	Related *LinkProperty `json:"related,omitempty"`
}

// Relationship defines model for Relationship.
type Relationship struct {
	Data struct {
		Id openapi_types.UUID `json:"id"`

		// Type Type of the related resource
		Type string `json:"type"`
	} `json:"data"`
	Links RelatedLink `json:"links"`

	// Meta Free-form object that may contain non-standard information.
	Meta *Meta `json:"meta,omitempty"`
}

// SelfLink defines model for SelfLink.
type SelfLink struct {
	Self *LinkProperty `json:"self,omitempty"`
}

// Tag defines model for Tag.
type Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Types defines model for Types.
type Types = string

// EndingBefore defines model for EndingBefore.
type EndingBefore = string

// Limit defines model for Limit.
type Limit = int32

// MetaCount defines model for MetaCount.
type MetaCount string

// StartingAfter defines model for StartingAfter.
type StartingAfter = string

// Version Requested API version
type Version = QueryVersion

// N400 defines model for 400.
type N400 = ErrorDocument

// N401 defines model for 401.
type N401 = ErrorDocument

// N403 defines model for 403.
type N403 = ErrorDocument

// N404 defines model for 404.
type N404 = ErrorDocument

// N409 defines model for 409.
type N409 = ErrorDocument

// N410 defines model for 410.
type N410 = ErrorDocument

// N500 defines model for 500.
type N500 = ErrorDocument

// AsLinkProperty0 returns the union data inside the LinkProperty as a LinkProperty0
func (t LinkProperty) AsLinkProperty0() (LinkProperty0, error) {
	var body LinkProperty0
	err := json.Unmarshal(t.union, &body)
	return body, err
}

// FromLinkProperty0 overwrites any union data inside the LinkProperty as the provided LinkProperty0
func (t *LinkProperty) FromLinkProperty0(v LinkProperty0) error {
	b, err := json.Marshal(v)
	t.union = b
	return err
}

// MergeLinkProperty0 performs a merge with any union data inside the LinkProperty, using the provided LinkProperty0
func (t *LinkProperty) MergeLinkProperty0(v LinkProperty0) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	merged, err := runtime.JsonMerge(t.union, b)
	t.union = merged
	return err
}

// AsLinkProperty1 returns the union data inside the LinkProperty as a LinkProperty1
func (t LinkProperty) AsLinkProperty1() (LinkProperty1, error) {
	var body LinkProperty1
	err := json.Unmarshal(t.union, &body)
	return body, err
}

// FromLinkProperty1 overwrites any union data inside the LinkProperty as the provided LinkProperty1
func (t *LinkProperty) FromLinkProperty1(v LinkProperty1) error {
	b, err := json.Marshal(v)
	t.union = b
	return err
}

// MergeLinkProperty1 performs a merge with any union data inside the LinkProperty, using the provided LinkProperty1
func (t *LinkProperty) MergeLinkProperty1(v LinkProperty1) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	merged, err := runtime.JsonMerge(t.union, b)
	t.union = merged
	return err
}

func (t LinkProperty) MarshalJSON() ([]byte, error) {
	b, err := t.union.MarshalJSON()
	return b, err
}

func (t *LinkProperty) UnmarshalJSON(b []byte) error {
	err := t.union.UnmarshalJSON(b)
	return err
}
