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

func TestEmptyInspectRedirectsHome(t *testing.T) {
	server := newTestServer(t)
	recorder := httptest.NewRecorder()
	server.handleInspect(recorder, httptest.NewRequest(http.MethodGet, "/inspect", nil))
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/" {
		t.Fatalf("status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
}

func TestUVYDesignComplianceAndOptionalVersionFooter(t *testing.T) {
	cfg := config.Config{
		Version:         "v1.2.3",
		ShowVersion:     true,
		AllowedList:     []string{"ghcr.io"},
		AllowedRegistry: map[string]bool{"ghcr.io": true},
	}
	service := inspect.NewService(cfg, nil, cache.NewMemory[*inspect.Report](), nil)
	server, err := New(cfg, service, nil)
	if err != nil {
		t.Fatal(err)
	}

	var rendered bytes.Buffer
	if err := server.templates.ExecuteTemplate(&rendered, "index.html", IndexData{Allowed: cfg.AllowedList}); err != nil {
		t.Fatal(err)
	}
	html := rendered.String()
	for _, want := range []string{
		"/static/css/uvy.css",
		"/static/js/uvy.js",
		`class="uvy-mark"`,
		`id="theme"`,
		"UnitVectorY-Labs",
		"MIT License",
		"on GitHub",
		`<p class="version">Version v1.2.3</p>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html missing %q", want)
		}
	}
	if strings.Contains(html, "UVY") {
		t.Error("index.html contains forbidden UVY brand abbreviation")
	}
	if strings.Contains(html, `style="`) {
		t.Error("index.html contains inline style attribute violating CSP style-src 'self'")
	}

	// Verify .version is omitted completely when ShowVersion is false.
	cfg.ShowVersion = false
	serverNoVer, err := New(cfg, service, nil)
	if err != nil {
		t.Fatal(err)
	}
	rendered.Reset()
	if err := serverNoVer.templates.ExecuteTemplate(&rendered, "index.html", IndexData{Allowed: cfg.AllowedList}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered.String(), `class="version"`) || strings.Contains(rendered.String(), "v1.2.3") {
		t.Error("footer rendered version when ShowVersion is false")
	}
}

func TestOriginCheckBlocksCrossSitePost(t *testing.T) {
	server := newTestServer(t)
	handler := server.wrapWithOriginCheck(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/inspect", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestLoadingPollTargetsConnectedShellAndOpenTabTargetsExist(t *testing.T) {
	server := newTestServer(t)

	var loadingBuf bytes.Buffer
	if err := server.templates.ExecuteTemplate(&loadingBuf, "results.html", ResultData{
		Input:   "ghcr.io/example/app:latest",
		Loading: &LoadingData{JobID: "abc123", Input: "ghcr.io/example/app:latest"},
	}); err != nil {
		t.Fatal(err)
	}
	loadingHTML := loadingBuf.String()
	for _, want := range []string{`id="inspection-shell"`, `hx-target="#inspection-shell"`, `hx-swap="innerHTML"`} {
		if !strings.Contains(loadingHTML, want) {
			t.Errorf("loading shell missing %q", want)
		}
	}

	report := &inspect.Report{
		Registry: "ghcr.io", Repository: "example/app", ResolvedDigest: "sha256:abc",
		TopLevel: inspect.TargetResult{Kind: "Image index"},
		Platforms: []inspect.TargetResult{{
			Name: "linux/amd64", Kind: "Platform manifest", OS: "linux", Architecture: "amd64",
			Layers:       []inspect.LayerDescriptor{{Index: 1, Digest: "sha256:111", Size: 100}},
			Config:       &inspect.ImageConfig{User: "65532:65532"},
			Attestations: []inspect.Artifact{{ID: "att1", Provenance: &inspect.ProvenanceDetail{SLSAVersion: "SLSA v1.0"}}},
			Signatures:   []inspect.Artifact{{ID: "sig1", Signature: &inspect.SignatureDetail{Signer: "test"}}},
			SBOMs:        []inspect.Artifact{{ID: "sbom1", SBOM: &inspect.SBOMDetail{Format: "SPDX-2.3", TotalComponents: 1, TotalComponentsLabel: "1"}}},
		}},
	}
	var reportBuf bytes.Buffer
	if err := server.templates.ExecuteTemplate(&reportBuf, "result-panel.html", ResultData{Report: report}); err != nil {
		t.Fatal(err)
	}
	reportHTML := reportBuf.String()
	for _, tabID := range []string{"p0-tab-evidence", "p0-tab-sbom", "p0-tab-layers", "p0-tab-config"} {
		if !strings.Contains(reportHTML, `data-open-tab="`+tabID+`"`) {
			t.Errorf("missing quick-jump button for %s", tabID)
		}
		if !strings.Contains(reportHTML, `id="`+tabID+`" role="tab"`) {
			t.Errorf("missing matching tab element for %s", tabID)
		}
	}
}
