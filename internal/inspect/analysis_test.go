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
	if component.Name != "base-files" || component.Version != "12.4" || component.Ecosystem != "deb" || component.Platform != "amd64" {
		t.Fatalf("component = %#v", component)
	}
}

func TestParseImagePURLPreservesHumanTag(t *testing.T) {
	name, tag, ok := parseImagePURL("pkg:docker/gcr.io/distroless/base-debian13@latest?platform=linux%2Famd64")
	if !ok || name != "gcr.io/distroless/base-debian13" || tag != "latest" {
		t.Fatalf("got name=%q tag=%q ok=%v", name, tag, ok)
	}
}
