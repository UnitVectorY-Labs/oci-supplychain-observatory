package inspect

import "testing"

func TestAnalyzeSPDXArtifactBuildsComponentInventory(t *testing.T) {
	artifact := Artifact{
		Type: "Attestation",
		Raw: []byte(`{
			"_type":"https://in-toto.io/Statement/v1",
			"predicateType":"https://spdx.dev/Document",
			"subject":[{"name":"example/image","digest":{"sha256":"abc"}}],
			"predicate":{
				"spdxVersion":"SPDX-2.3",
				"name":"example SBOM",
				"creationInfo":{"creators":["Tool: scanner 1.0"]},
				"packages":[{
					"name":"base-files",
					"versionInfo":"12.4",
					"supplier":"Organization: Debian",
					"licenseConcluded":"NOASSERTION",
					"licenseDeclared":"MIT",
					"externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:deb/debian/base-files@12.4?arch=amd64"}]
				}],
				"relationships":[]
			}
		}`),
	}
	analyzeArtifact(&artifact)
	if artifact.Purpose != "SPDX SBOM" || artifact.Type != "SBOM attestation" {
		t.Fatalf("purpose/type = %q/%q", artifact.Purpose, artifact.Type)
	}
	if len(artifact.Components) != 1 {
		t.Fatalf("components = %#v", artifact.Components)
	}
	component := artifact.Components[0]
	if component.Name != "base-files" || component.Version != "12.4" || component.Ecosystem != "deb" || component.Platform != "amd64" || component.License != "MIT" {
		t.Fatalf("component = %#v", component)
	}
}

func TestParseImagePURLPreservesHumanTag(t *testing.T) {
	name, tag, ok := parseImagePURL("pkg:docker/gcr.io/distroless/base-debian13@latest?platform=linux%2Famd64")
	if !ok || name != "gcr.io/distroless/base-debian13" || tag != "latest" {
		t.Fatalf("got name=%q tag=%q ok=%v", name, tag, ok)
	}
}

func TestAnalyzeCycloneDXIncludesNestedComponentsAndLicenses(t *testing.T) {
	artifact := Artifact{Type: "Attestation", Raw: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"app","components":[{"name":"openssl","version":"3.0","licenses":[{"license":{"id":"Apache-2.0"}}]}]}]}`)}
	analyzeArtifact(&artifact)
	if len(artifact.Components) != 2 || artifact.Components[1].Name != "openssl" || artifact.Components[1].License != "Apache-2.0" {
		t.Fatalf("components = %#v", artifact.Components)
	}
	for _, fact := range artifact.Facts {
		if fact.Key == "Components" && fact.Value == "2" {
			return
		}
	}
	t.Fatalf("missing nested component count: %#v", artifact.Facts)
}

func TestAnalyzeSPDXDecodesStringPredicate(t *testing.T) {
	artifact := Artifact{Type: "Attestation", Raw: []byte(`{"predicateType":"https://spdx.dev/Document","predicate":"{\"spdxVersion\":\"SPDX-2.3\",\"packages\":[{\"name\":\"base\"}]}"}`)}
	analyzeArtifact(&artifact)
	if len(artifact.Components) != 1 || artifact.Components[0].Name != "base" {
		t.Fatalf("components = %#v, facts=%#v", artifact.Components, artifact.Facts)
	}
}

func TestAnalyzeSLSA02IncludesConfigCommit(t *testing.T) {
	artifact := Artifact{Type: "Attestation", Raw: []byte(`{"predicateType":"https://slsa.dev/provenance/v0.2","predicate":{"buildType":"example","invocation":{"configSource":{"uri":"https://github.com/example/app","digest":{"sha1":"abc123"}}}}}`)}
	analyzeArtifact(&artifact)
	for _, fact := range artifact.Facts {
		if fact.Key == "Source ref" && fact.Value == "sha1:abc123" {
			return
		}
	}
	t.Fatalf("missing config source commit: %#v", artifact.Facts)
}

func TestUnsupportedSBOMDoesNotClaimEmptyInventory(t *testing.T) {
	for _, typ := range []string{"spdx", "cyclonedx"} {
		artifact := Artifact{Raw: []byte(`{"predicateType":"` + typ + `","predicate":"not a supported document"}`)}
		analyzeArtifact(&artifact)
		found := false
		for _, fact := range artifact.Facts {
			if fact.Key == "Components" {
				t.Errorf("%s claims a component count for an unsupported document", typ)
			}
			if fact.Key == "Inventory" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s missing explicit inventory limitation", typ)
		}
	}
}

func TestStringPredicatePreservesSubjectsAndLineage(t *testing.T) {
	raw := []byte(`{"subject":[{"name":"app"}],"predicate":"{\"materials\":[{\"uri\":\"pkg:docker/library/alpine@3.20\",\"digest\":{\"sha256\":\"abc\"}}]}"}`)
	doc, ok := decodeArtifactDocument(raw)
	if !ok || doc["subject"] == nil {
		t.Fatal("statement subjects lost")
	}
	if got := artifactDependencies(raw); len(got) != 1 || got[0].Digest != "sha256:abc" {
		t.Fatalf("lineage = %#v", got)
	}
}
