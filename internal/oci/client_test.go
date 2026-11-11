package oci

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGetManifestJSONParsing(t *testing.T) {
	for _, tc := range []struct {
		name, body    string
		wantError     bool
		wantMediaType string
	}{
		{"valid", `{"mediaType":"example"}`, false, "example"},
		{"duplicate key", `{"mediaType":"one","mediaType":"two"}`, true, ""},
		{"invalid UTF-8", "{\"mediaType\":\"\xff\"}", true, ""},
		{"case sensitive field", `{"MediaType":"example"}`, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &Client{http: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}}
			_, manifest, err := client.GetManifest(context.Background(), "example.com", "repo", "tag")
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, want error %v", err, tc.wantError)
			}
			if manifest.MediaType != tc.wantMediaType {
				t.Fatalf("media type = %q, want %q", manifest.MediaType, tc.wantMediaType)
			}
		})
	}
}
