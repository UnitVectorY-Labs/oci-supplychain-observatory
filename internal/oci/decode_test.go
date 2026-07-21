package oci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

func TestLegacyCosignTag(t *testing.T) {
	got := LegacyCosignTag("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ".sig")
	want := "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sig"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSummarizeJSONDetectsCycloneDX(t *testing.T) {
	summary, _, isSBOM := SummarizeJSON([]byte(`{"bomFormat":"CycloneDX","components":[{},{}]}`))
	if !isSBOM {
		t.Fatal("expected SBOM")
	}
	if len(summary) == 0 {
		t.Fatal("expected summary")
	}
}

func TestSummarizeJSONExpandsJSONStringPredicate(t *testing.T) {
	summary, _, isSBOM := SummarizeJSON([]byte(`{"predicateType":"https://spdx.dev/Document","predicate":"{\"spdxVersion\":\"SPDX-2.3\",\"packages\":[{},{}]}"}`))
	if !isSBOM {
		t.Fatal("expected SBOM")
	}
	for _, item := range summary {
		if item.Key == "Package count" && item.Value == "2" {
			return
		}
	}
	t.Fatalf("missing package count in %#v", summary)
}

func TestBuildPayloadViewsExpandsBase64JSONFields(t *testing.T) {
	raw := []byte(`{"payload":"eyJzdWJqZWN0IjpbeyJuYW1lIjoiaW1hZ2UiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjIn19XX0="}`)
	views := BuildPayloadViews(raw, 4096)
	if !views.DecodedJSON {
		t.Fatal("expected decoded JSON")
	}
	if !views.DecodedChanged {
		t.Fatal("expected decoded structure to change")
	}
	if len(views.Rows) == 0 {
		t.Fatal("expected decoded rows")
	}
	payload := findPayloadRow(views.Rows, "payload")
	if payload == nil {
		t.Fatalf("missing payload row in %#v", views.Rows)
	}
	if payload.Type != "decoded base64 JSON" {
		t.Fatalf("payload type = %q, want decoded base64 JSON", payload.Type)
	}
	if len(payload.DecodedRows) == 0 {
		t.Fatalf("payload did not keep decoded rows: %#v", payload)
	}
	subject := findPayloadRowDeep(payload.DecodedRows, "subject")
	digest := findPayloadRowDeep(payload.DecodedRows, "sha256")
	if subject == nil || digest == nil || digest.Value != "abc" {
		t.Fatalf("decoded payload rows missing expected structure: %#v", payload.DecodedRows)
	}
}

func TestBuildPayloadViewsKeepsNumericStringsAsStrings(t *testing.T) {
	raw := []byte(`{"logIndex":"1796021218","treeSize":"1796021231","integratedTime":"1782168928"}`)
	views := BuildPayloadViews(raw, 4096)
	for _, key := range []string{"logIndex", "treeSize", "integratedTime"} {
		row := findPayloadRow(views.Rows, key)
		if row == nil {
			t.Fatalf("missing row %q in %#v", key, views.Rows)
		}
		if row.Type != "string" {
			t.Fatalf("row %q type = %q, want string", key, row.Type)
		}
	}
}

func TestBuildPayloadViewsDecodesCertificateRawBytes(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "leaf.example"},
		Issuer:       pkix.Name{CommonName: "leaf.example"},
		NotBefore:    time.Unix(1000, 0),
		NotAfter:     time.Unix(2000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"verificationMaterial":{"certificate":{"rawBytes":"` + base64.StdEncoding.EncodeToString(der) + `"}}}`)
	views := BuildPayloadViews(raw, 4096)
	rawBytes := findPayloadRow(views.Rows, "rawBytes")
	if rawBytes == nil || rawBytes.Type != "decoded x509 certificate" {
		t.Fatalf("rawBytes row = %#v", rawBytes)
	}
	subject := findPayloadRowDeep(rawBytes.DecodedRows, "subject")
	if subject == nil || subject.Value == "" {
		t.Fatalf("missing decoded certificate subject in %#v", rawBytes.DecodedRows)
	}
}

func TestFieldGuidanceExplainsSupplyChainSemantics(t *testing.T) {
	label, meaning := FieldGuidance("predicateType")
	if label != "Claim type" || meaning == "" {
		t.Fatalf("guidance = %q, %q", label, meaning)
	}
	label, meaning = FieldGuidance("vendorExtension")
	if label != "Vendor Extension" || meaning == "" {
		t.Fatalf("fallback guidance = %q, %q", label, meaning)
	}
}

func TestExtractBuildMaterialsFromDSSEProvenance(t *testing.T) {
	statement := `{"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"resolvedDependencies":[{"uri":"pkg:docker/gcr.io/distroless/base-debian13","digest":{"sha256":"abc"}}]}}}`
	raw := []byte(`{"payload":"` + base64.StdEncoding.EncodeToString([]byte(statement)) + `"}`)
	materials := ExtractBuildMaterials(raw)
	if len(materials) != 1 {
		t.Fatalf("materials = %#v", materials)
	}
	if materials[0].URI != "pkg:docker/gcr.io/distroless/base-debian13" || materials[0].Digests["sha256"] != "abc" {
		t.Fatalf("material = %#v", materials[0])
	}
}

func findPayloadRow(rows []PayloadRow, key string) *PayloadRow {
	for i := range rows {
		if rows[i].Key == key {
			return &rows[i]
		}
	}
	return nil
}

func findPayloadRowDeep(rows []PayloadRow, key string) *PayloadRow {
	for i := range rows {
		if rows[i].Key == key {
			return &rows[i]
		}
		if row := findPayloadRowDeep(rows[i].DecodedRows, key); row != nil {
			return row
		}
	}
	return nil
}
