package testutil

import (
	"fmt"
	"github.com/google/uuid"
	"net/http"
	"os"
)

type TestAuthRoundTripper struct {
	http.RoundTripper
}

func (tart TestAuthRoundTripper) RoundTrip(req *http.Request) (res *http.Response, e error) {
	token := os.Getenv("SMOKE_TEST_TOKEN")
	if token == "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", uuid.New().String()))
	} else {
		req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
	}
	return tart.RoundTripper.RoundTrip(req)
}
