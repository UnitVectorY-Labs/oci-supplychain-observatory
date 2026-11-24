package oci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func TestParseNextReferrerPathRestrictsHostAndScheme(t *testing.T) {
	tests := []struct {
		name         string
		link         string
		expectedHost string
		want         string
	}{
		{
			name:         "relative v2 path",
			link:         `</v2/org/repo/referrers/sha256:abc?n=50>; rel="next"`,
			expectedHost: "ghcr.io",
			want:         "/v2/org/repo/referrers/sha256:abc?n=50",
		},
		{
			name:         "same host https url",
			link:         `<https://ghcr.io/v2/org/repo/referrers/sha256:abc?last=xyz>; rel="next"`,
			expectedHost: "ghcr.io",
			want:         "/v2/org/repo/referrers/sha256:abc?last=xyz",
		},
		{
			name:         "cross host rejected",
			link:         `<https://evil.example/v2/org/repo/referrers/sha256:abc>; rel="next"`,
			expectedHost: "ghcr.io",
			want:         "",
		},
		{
			name:         "http scheme rejected",
			link:         `<http://ghcr.io/v2/org/repo/referrers/sha256:abc>; rel="next"`,
			expectedHost: "ghcr.io",
			want:         "",
		},
		{
			name:         "non v2 path rejected",
			link:         `</admin/secret>; rel="next"`,
			expectedHost: "ghcr.io",
			want:         "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseNextReferrerPath(tt.link, tt.expectedHost); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClientTokenCacheLifecycle(t *testing.T) {
	c := NewClient(5 * time.Second)
	c.setCachedToken("ghcr.io\x00org/repo", "tok-1", time.Minute)
	if got := c.getCachedToken("ghcr.io\x00org/repo"); got != "tok-1" {
		t.Fatalf("got %q, want tok-1", got)
	}
	c.deleteCachedToken("ghcr.io\x00org/repo")
	if got := c.getCachedToken("ghcr.io\x00org/repo"); got != "" {
		t.Fatalf("expected empty after delete, got %q", got)
	}
}

func TestParseCertificateExtractsFulcioOIDsAndRekor(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sanURI, _ := url.Parse("https://github.com/UnitVectorY-Labs/oci-supplychain-observatory/.github/workflows/release.yml@refs/tags/v1.0.0")
	oidcVal, _ := asn1.Marshal("https://token.actions.githubusercontent.com")
	srcRepoVal, _ := asn1.Marshal("https://github.com/UnitVectorY-Labs/oci-supplychain-observatory")
	runnerVal, _ := asn1.Marshal("github-hosted")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "fulcio-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Minute),
		URIs:         []*url.URL{sanURI},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, Value: oidcVal},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}, Value: srcRepoVal},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 18}, Value: runnerVal},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	info, ok := ParseCertificate(base64.StdEncoding.EncodeToString(der))
	if !ok {
		t.Fatal("ParseCertificate failed")
	}
	if info.PrimaryIdentity() != sanURI.String() {
		t.Fatalf("PrimaryIdentity = %q", info.PrimaryIdentity())
	}
	if info.OIDCIssuer != "https://token.actions.githubusercontent.com" {
		t.Fatalf("OIDCIssuer = %q", info.OIDCIssuer)
	}
	if info.SourceRepoURI != "https://github.com/UnitVectorY-Labs/oci-supplychain-observatory" {
		t.Fatalf("SourceRepoURI = %q", info.SourceRepoURI)
	}
	if info.RunnerEnvironment != "github-hosted" {
		t.Fatalf("RunnerEnvironment = %q", info.RunnerEnvironment)
	}

	rekor := ExtractRekorInfo(nil, map[string]string{
		"dev.sigstore.cosign/bundle": `{"Payload":{"logIndex":12345,"integratedTime":1700000000,"logID":"deadbeef"}}`,
	})
	if rekor == nil || rekor.LogIndex != "12345" || rekor.LogID != "deadbeef" || rekor.IntegratedTime.Unix() != 1700000000 {
		t.Fatalf("unexpected rekor entry: %+v", rekor)
	}
}
