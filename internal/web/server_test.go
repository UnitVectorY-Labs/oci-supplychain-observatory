package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/cache"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/config"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/inspect"
)

func TestNewParsesTemplates(t *testing.T) {
	_ = newTestServer(t)
}

func TestFullPagesUsePinnedHTMX4WithIntegrity(t *testing.T) {
	server := newTestServer(t)
	tests := []struct {
		name string
		data any
	}{
		{name: "index.html", data: IndexData{Allowed: []string{"ghcr.io"}}},
		{name: "page-results.html", data: ResultData{Error: &ErrorData{Title: "Test", Message: "Test"}}},
	}
	const htmxURL = "https://unpkg.com/htmx.org@4.0.0/dist/htmx.min.js"
	const htmxIntegrity = "sha384-BvJpBiO8Kh31EqtJe5DRIeWrHWnCGkwytKs9NKFi86Hhw96dEqdEMzZDeK9iEGTc"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rendered bytes.Buffer
			if err := server.templates.ExecuteTemplate(&rendered, tt.name, tt.data); err != nil {
				t.Fatal(err)
			}
			html := rendered.String()
			for _, expected := range []string{
				`name="htmx-config" content='{"includeIndicatorCSS": false}'`,
				`src="` + htmxURL + `"`,
				`integrity="` + htmxIntegrity + `"`,
				`crossorigin="anonymous"`,
			} {
				if !strings.Contains(html, expected) {
					t.Errorf("rendered page does not contain %q", expected)
				}
			}
			if count := strings.Count(html, htmxURL); count != 1 {
				t.Errorf("HTMX URL occurs %d times, want 1", count)
			}
			if strings.Contains(html, "/static/js/htmx.min.js") {
				t.Error("rendered page still references the vendored HTMX bundle")
			}
		})
	}
}

func TestSecurityHeadersAllowPinnedHTMXOrigin(t *testing.T) {
	server := newTestServer(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	server.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, request)

	const expected = "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	if got := recorder.Header().Get("Content-Security-Policy"); got != expected {
		t.Fatalf("Content-Security-Policy = %q, want %q", got, expected)
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := config.Config{
		AllowedList:     []string{"ghcr.io"},
		AllowedRegistry: map[string]bool{"ghcr.io": true},
	}
	service := inspect.NewService(cfg, nil, cache.NewMemory[*inspect.Report](), nil)
	server, err := New(cfg, service, nil)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestReportOpensPlatformEvidenceAndDefersPayload(t *testing.T) {
	server := newTestServer(t)
	report := &inspect.Report{
		Registry: "ghcr.io", Repository: "example/app", ResolvedDigest: "sha256:abc",
		TopLevel:  inspect.TargetResult{Kind: "Image index"},
		Platforms: []inspect.TargetResult{{Name: "linux/arm64", Kind: "Platform manifest", OS: "linux", Architecture: "arm64", SBOMs: []inspect.Artifact{{ID: "test-artifact", Purpose: "SPDX SBOM", RawView: "raw-payload-sentinel", Downloadable: true, DecodedViewJSON: true}}}},
	}
	var rendered bytes.Buffer
	if err := server.templates.ExecuteTemplate(&rendered, "result-panel.html", ResultData{Report: report}); err != nil {
		t.Fatal(err)
	}
	html := rendered.String()
	for _, want := range []string{`data-default-target="target-platform-0"`, `aria-pressed="true">linux/arm64`, `/artifacts/test-artifact/view`, `Not verified`, `No policy trust evaluated`} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(html, "raw-payload-sentinel") {
		t.Error("initial report includes deferred raw payload")
	}
	if strings.Contains(html, "Found and parsed") {
		t.Error("report claims all artifacts were parsed")
	}
}

func TestArtifactPayloadEscapesRegistryContent(t *testing.T) {
	server := newTestServer(t)
	var rendered bytes.Buffer
	artifact := &inspect.Artifact{RawView: `<script>alert("registry")</script>`}
	if err := server.templates.ExecuteTemplate(&rendered, "payload-view", artifact); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered.String(), `<script>alert`) || !strings.Contains(rendered.String(), `&lt;script&gt;`) {
		t.Fatal("payload must be escaped")
	}
}

func TestInvalidNavigationRendersFullPage(t *testing.T) {
	server := newTestServer(t)
	recorder := httptest.NewRecorder()
	server.handleInspect(recorder, httptest.NewRequest(http.MethodGet, "/inspect?image=not-allowed.example/repo:tag", nil))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "<!doctype html>") {
		t.Fatalf("expected complete error page, status=%d", recorder.Code)
	}
}

func TestUnknownArtifactViewReturnsNotFound(t *testing.T) {
	server := newTestServer(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/artifacts/missing/view", nil)
	request.SetPathValue("id", "missing")
	server.handleArtifactView(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d", recorder.Code)
	}
}
