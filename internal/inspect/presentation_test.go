package inspect

import "testing"

func TestDefaultScopeAndSingleManifestCount(t *testing.T) {
	report := Report{TopLevel: TargetResult{Kind: "Image manifest", OS: "linux", Architecture: "arm64", Variant: "v8"}}
	if report.PlatformCount() != 1 || report.DefaultTargetID() != "target-top" || report.TopLevel.ScopeLabel() != "linux/arm64/v8" {
		t.Fatalf("single-manifest presentation: %#v", report)
	}
	report.TopLevel.Kind = "Image index"
	report.Platforms = []TargetResult{{Name: "linux/amd64"}, {Name: "linux/arm64", SBOMs: []Artifact{{}}}}
	if report.DefaultTargetID() != "target-platform-1" || report.PlatformCount() != 2 {
		t.Fatalf("evidence scope not selected: %s", report.DefaultTargetID())
	}
}

func TestDecodeStatusNeverClaimsParsingFailedArtifact(t *testing.T) {
	for _, tc := range []struct {
		artifact Artifact
		want     string
	}{
		{Artifact{Error: "too large", DecodedViewJSON: true}, "Unavailable"},
		{Artifact{DecodedViewJSON: true}, "Decoded"},
		{Artifact{Downloadable: true}, "Found · unsupported format"},
		{Artifact{}, "Discovered"},
	} {
		if got := tc.artifact.DecodeStatus(); got != tc.want {
			t.Errorf("status = %q, want %q", got, tc.want)
		}
	}
}
