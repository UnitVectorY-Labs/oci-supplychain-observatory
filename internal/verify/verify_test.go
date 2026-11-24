package verify

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func makeECDSACert(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, []byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("https://github.com/UnitVectorY-Labs/example/.github/workflows/release.yml@refs/tags/v1.0.0")
	issuerVal, _ := asn1.Marshal("https://token.actions.githubusercontent.com")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test-signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{u},
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8},
			Value: issuerVal,
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return key, der, pemText
}

func TestVerifyCosignSimpleSigningValidAndTampered(t *testing.T) {
	key, _, certPEM := makeECDSACert(t, elliptic.P256())
	payload := []byte(`{"critical":{"image":{"docker-manifest-digest":"sha256:1111"},"type":"cosign container image signature"}}`)
	digest := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	annots := map[string]string{
		"dev.cosignproject.cosign/signature": base64.StdEncoding.EncodeToString(sig),
		"dev.sigstore.cosign/certificate":    certPEM,
		"dev.sigstore.cosign/bundle":         `{"Payload":{"logIndex":98765,"integratedTime":1700000000,"logID":"abc123"}}`,
	}

	res := Artifact(payload, annots, "sha256:1111", []string{"sha256:1111"})
	if res.State != StateSignatureValid {
		t.Fatalf("got state %q (%s), want %q", res.State, res.Detail, StateSignatureValid)
	}
	if res.PolicyEvaluated {
		t.Fatal("expected PolicyEvaluated=false")
	}
	if res.SubjectMatch != SubjectMatches {
		t.Fatalf("got subject match %q, want %q", res.SubjectMatch, SubjectMatches)
	}
	if res.Certificate == nil || res.Certificate.OIDCIssuer != "https://token.actions.githubusercontent.com" {
		t.Fatalf("expected parsed Fulcio OIDC issuer, got %+v", res.Certificate)
	}
	if res.Rekor == nil || res.Rekor.LogIndex != "98765" {
		t.Fatalf("expected Rekor log index 98765, got %+v", res.Rekor)
	}

	// Tamper with payload
	tampered := []byte(`{"critical":{"image":{"docker-manifest-digest":"sha256:2222"},"type":"cosign container image signature"}}`)
	bad := Artifact(tampered, annots, "sha256:1111", []string{"sha256:2222"})
	if bad.State != StateSignatureInvalid {
		t.Fatalf("got tampered state %q, want %q", bad.State, StateSignatureInvalid)
	}
	if bad.SubjectMatch != SubjectMismatch {
		t.Fatalf("got tampered subject match %q, want %q", bad.SubjectMatch, SubjectMismatch)
	}
}

func TestVerifySigstoreBundleDSSE(t *testing.T) {
	key, der, _ := makeECDSACert(t, elliptic.P256())
	stmt := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"sha256":"aaaa"}}],"predicateType":"https://slsa.dev/provenance/v1"}`)
	payloadType := "application/vnd.in-toto+json"
	pae := dssePAE(payloadType, stmt)
	sum := sha256.Sum256(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
		"verificationMaterial": map[string]any{
			"certificate": map[string]any{"rawBytes": base64.StdEncoding.EncodeToString(der)},
			"tlogEntries": []any{map[string]any{"logIndex": "42", "integratedTime": "1700000000"}},
		},
		"dsseEnvelope": map[string]any{
			"payloadType": payloadType,
			"payload":     base64.StdEncoding.EncodeToString(stmt),
			"signatures":  []any{map[string]any{"sig": base64.StdEncoding.EncodeToString(sig)}},
		},
	}
	raw, _ := json.Marshal(bundle)

	res := Artifact(raw, nil, "sha256:aaaa", []string{"sha256:aaaa"})
	if res.State != StateSignatureValid {
		t.Fatalf("got state %q (%s), want %q", res.State, res.Detail, StateSignatureValid)
	}
	if res.Rekor == nil || res.Rekor.LogIndex != "42" {
		t.Fatalf("expected Rekor log index 42, got %+v", res.Rekor)
	}
}

func TestVerifyEd25519AndMissingCert(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "ed25519-signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"test":"ed25519"}`)
	sig := ed25519.Sign(priv, payload)
	annots := map[string]string{
		"dev.cosignproject.cosign/signature": base64.StdEncoding.EncodeToString(sig),
		"dev.sigstore.cosign/certificate":    base64.StdEncoding.EncodeToString(der),
	}
	res := Artifact(payload, annots, "", nil)
	if res.State != StateSignatureValid || res.Algorithm != "Ed25519" {
		t.Fatalf("got %+v, want valid Ed25519", res)
	}

	// Signature without certificate -> unverified (not invalid)
	noCert := Artifact(payload, map[string]string{"dev.cosignproject.cosign/signature": base64.StdEncoding.EncodeToString(sig)}, "", nil)
	if noCert.State != StateUnverified {
		t.Fatalf("got state %q, want %q", noCert.State, StateUnverified)
	}

	// Short dev.sigstore.cosign/cert annotation key (used by Cosign v2 keyless)
	shortCert := Artifact(payload, map[string]string{
		"dev.cosignproject.cosign/signature": base64.StdEncoding.EncodeToString(sig),
		"dev.sigstore.cosign/cert":           base64.StdEncoding.EncodeToString(der),
	}, "", nil)
	if shortCert.State != StateSignatureValid {
		t.Fatalf("dev.sigstore.cosign/cert got state %q (%s), want %q", shortCert.State, shortCert.Detail, StateSignatureValid)
	}
}
