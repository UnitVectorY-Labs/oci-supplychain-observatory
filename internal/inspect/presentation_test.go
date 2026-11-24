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

func TestDiscoveryLabelShortensLongCosignTags(t *testing.T) {
	a := Artifact{Discovery: "Cosign legacy tag sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sig"}
	if got := a.DiscoveryLabel(); got != "Cosign .sig tag" {
		t.Fatalf("got %q, want Cosign .sig tag", got)
	}
	b := Artifact{Discovery: "Image index attestation manifest"}
	if got := b.DiscoveryLabel(); got != "Index attestation" {
		t.Fatalf("got %q, want Index attestation", got)
	}
}

func TestFilterComponentsSearchFacetAndPagination(t *testing.T) {
	a := Artifact{
		ID: "sbom-1",
		SBOM: &SBOMDetail{
			TotalComponents: 3,
			AllComponents: []Component{
				{Name: "openssl", Version: "3.0.1", Ecosystem: "deb", License: "Apache-2.0"},
				{Name: "cosign", Version: "2.4.1", Ecosystem: "golang", License: "Apache-2.0"},
				{Name: "zlib", Version: "1.3.1", Ecosystem: "deb", License: "Zlib"},
			},
		},
	}
	page := a.FilterComponents("", "deb", "", 1, 1)
	if page.TotalMatched != 2 || page.TotalPages != 2 || len(page.Items) != 1 || !page.HasNext || page.HasPrev {
		t.Fatalf("unexpected page 1: %+v", page)
	}
	page2 := a.FilterComponents("zlib", "deb", "Zlib", 1, 50)
	if page2.TotalMatched != 1 || len(page2.Items) != 1 || page2.Items[0].Name != "zlib" {
		t.Fatalf("unexpected filtered page: %+v", page2)
	}
}

func TestCleanHistoryCommand(t *testing.T) {
	if got := cleanHistoryCommand("/bin/sh -c #(nop) COPY /server /server"); got != "COPY /server /server" {
		t.Fatalf("got %q", got)
	}
	if got := cleanHistoryCommand("/bin/sh -c apt-get update"); got != "RUN apt-get update" {
		t.Fatalf("got %q", got)
	}
}
