// Package verify performs explicit, stdlib-only cryptographic signature checks
// against embedded X.509 certificates without evaluating trust chains or policies.
package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/oci"
)

const (
	StateSignatureValid   = "signature-valid"
	StateSignatureInvalid = "signature-invalid"
	StateUnverified       = "unverified"

	SubjectMatches  = "matches"
	SubjectMismatch = "mismatch"
	SubjectUnknown  = "unknown"
)

type Result struct {
	State           string
	Label           string
	Detail          string
	Algorithm       string
	SubjectMatch    string
	PolicyEvaluated bool
	Certificate     *oci.CertificateInfo
	Rekor           *oci.RekorEntry
}

func (r Result) StatusClass() string {
	switch r.State {
	case StateSignatureValid:
		return "uvy-status--ok"
	case StateSignatureInvalid:
		return "uvy-status--danger"
	default:
		return ""
	}
}

func (r Result) DisplayLabel() string {
	if r.Label != "" {
		return r.Label
	}
	switch r.State {
	case StateSignatureValid:
		return "Signature valid (embedded cert)"
	case StateSignatureInvalid:
		return "Signature invalid"
	default:
		return "Not verified"
	}
}

// Artifact verifies cryptographic signatures where both a signature and an
// embedded X.509 certificate are present in the artifact payload or its
// descriptor annotations. It never evaluates certificate chains or trust policy.
func Artifact(raw []byte, annotations map[string]string, targetDigest string, claimedDigests []string) Result {
	res := Result{
		State:           StateUnverified,
		Label:           "Not verified",
		Detail:          "No embedded certificate and signature pair was available to verify. No trust policy evaluated.",
		SubjectMatch:    checkSubjectMatch(targetDigest, claimedDigests),
		PolicyEvaluated: false,
		Rekor:           oci.ExtractRekorInfo(raw, annotations),
	}

	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)

	certRaw := extractCertificateRaw(doc, annotations)
	if certRaw != "" {
		if info, ok := oci.ParseCertificate(certRaw); ok {
			res.Certificate = info
		}
	}

	cert, certErr := oci.ParseX509Certificate(certRaw)

	// 1. Sigstore bundle or standalone DSSE envelope.
	if env := extractDSSE(doc); env != nil {
		if len(env.sigs) == 0 {
			res.Detail = "DSSE envelope contains no signatures. No trust policy evaluated."
			return res
		}
		if certErr != nil || cert == nil {
			res.Detail = "DSSE signature is present, but no embedded X.509 certificate was published with it. No trust policy evaluated."
			return res
		}
		payloadBytes, ok := decodeBase64Bytes(env.payload)
		if !ok {
			res.State = StateSignatureInvalid
			res.Label = "Signature invalid"
			res.Detail = "DSSE payload could not be base64-decoded for signature verification."
			return res
		}
		pae := dssePAE(env.payloadType, payloadBytes)
		for _, sigB64 := range env.sigs {
			sigBytes, ok := decodeBase64Bytes(sigB64)
			if !ok {
				continue
			}
			if alg, valid := verifyWithCertificate(cert, pae, sigBytes); valid {
				res.State = StateSignatureValid
				res.Label = "Signature valid (embedded cert)"
				res.Algorithm = alg
				res.Detail = fmt.Sprintf("DSSE %s signature verified against the embedded X.509 certificate public key. Certificate chain, Rekor inclusion proof, and trust policy were not evaluated.", alg)
				return res
			}
		}
		res.State = StateSignatureInvalid
		res.Label = "Signature invalid"
		res.Detail = "DSSE signature did not verify against the embedded X.509 certificate public key."
		return res
	}

	// 2. Sigstore bundle messageSignature (raw digest/signature) or Cosign JSON Payload/Base64Signature.
	if doc != nil {
		if sigB64, ok := doc["Base64Signature"].(string); ok && strings.TrimSpace(sigB64) != "" {
			if certErr != nil || cert == nil {
				res.Detail = "Cosign signature is present, but no embedded X.509 certificate was published with it. No trust policy evaluated."
				return res
			}
			payloadStr, _ := doc["Payload"].(string)
			payloadBytes := []byte(payloadStr)
			if decoded, ok := decodeBase64Bytes(payloadStr); ok && json.Valid(decoded) {
				payloadBytes = decoded
			}
			sigBytes, ok := decodeBase64Bytes(sigB64)
			if ok {
				if alg, valid := verifyWithCertificate(cert, payloadBytes, sigBytes); valid {
					res.State = StateSignatureValid
					res.Label = "Signature valid (embedded cert)"
					res.Algorithm = alg
					res.Detail = fmt.Sprintf("Cosign %s signature verified against the embedded X.509 certificate public key. Certificate chain and trust policy were not evaluated.", alg)
					return res
				}
			}
			res.State = StateSignatureInvalid
			res.Label = "Signature invalid"
			res.Detail = "Cosign signature did not verify against the embedded X.509 certificate public key."
			return res
		}
	}

	// 3. Cosign simple-signing OCI layer with dev.cosignproject.cosign/signature annotation.
	if sigB64 := annotationLookup(annotations, "signature"); sigB64 != "" {
		if certErr != nil || cert == nil {
			res.Detail = "OCI signature annotation is present, but no embedded X.509 certificate was published with it (it may be key-signed). No trust policy evaluated."
			return res
		}
		sigBytes, ok := decodeBase64Bytes(sigB64)
		if !ok {
			res.State = StateSignatureInvalid
			res.Label = "Signature invalid"
			res.Detail = "OCI signature annotation was not valid base64."
			return res
		}
		if alg, valid := verifyWithCertificate(cert, raw, sigBytes); valid {
			res.State = StateSignatureValid
			res.Label = "Signature valid (embedded cert)"
			res.Algorithm = alg
			res.Detail = fmt.Sprintf("Cosign %s signature verified over the raw payload using the embedded X.509 certificate public key. Certificate chain, Rekor inclusion proof, and trust policy were not evaluated.", alg)
			return res
		}
		res.State = StateSignatureInvalid
		res.Label = "Signature invalid"
		res.Detail = "Cosign layer signature did not verify against the embedded X.509 certificate public key."
		return res
	}

	return res
}

type dsseEnvelope struct {
	payloadType string
	payload     string
	sigs        []string
}

func extractDSSE(doc map[string]any) *dsseEnvelope {
	if doc == nil {
		return nil
	}
	target := doc
	if nested, ok := doc["dsseEnvelope"].(map[string]any); ok {
		target = nested
	}
	payloadType, _ := target["payloadType"].(string)
	payload, _ := target["payload"].(string)
	if payloadType == "" || payload == "" {
		return nil
	}
	var sigs []string
	if rawSigs, ok := target["signatures"].([]any); ok {
		for _, item := range rawSigs {
			m, _ := item.(map[string]any)
			if sig, _ := m["sig"].(string); strings.TrimSpace(sig) != "" {
				sigs = append(sigs, sig)
			}
		}
	}
	return &dsseEnvelope{payloadType: payloadType, payload: payload, sigs: sigs}
}

func extractCertificateRaw(doc map[string]any, annotations map[string]string) string {
	if doc != nil {
		if material, ok := doc["verificationMaterial"].(map[string]any); ok {
			if cert, ok := material["certificate"].(map[string]any); ok {
				if raw, ok := cert["rawBytes"].(string); ok && strings.TrimSpace(raw) != "" {
					return raw
				}
			}
			if chain, ok := material["x509CertificateChain"].(map[string]any); ok {
				if certs, ok := chain["certificates"].([]any); ok && len(certs) > 0 {
					if first, ok := certs[0].(map[string]any); ok {
						if raw, ok := first["rawBytes"].(string); ok && strings.TrimSpace(raw) != "" {
							return raw
						}
					}
				}
			}
		}
		if cert, ok := doc["Cert"].(map[string]any); ok {
			if raw, ok := cert["Raw"].(string); ok && strings.TrimSpace(raw) != "" {
				return raw
			}
		}
	}
	if cert := annotationLookup(annotations, "certificate"); cert != "" {
		return cert
	}
	for k, v := range annotations {
		lower := strings.ToLower(k)
		if (strings.HasSuffix(lower, "/cert") || lower == "cert") && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func annotationLookup(annotations map[string]string, substr string) string {
	for k, v := range annotations {
		if strings.Contains(strings.ToLower(k), substr) && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// dssePAE computes DSSEv1 Pre-Authentication Encoding.
func dssePAE(payloadType string, payload []byte) []byte {
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	out := make([]byte, len(prefix)+len(payload))
	copy(out, prefix)
	copy(out[len(prefix):], payload)
	return out
}

func verifyWithCertificate(cert *x509.Certificate, data, sig []byte) (string, bool) {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		// Try the curve's natural hash first, then fall back to SHA-256/384/512.
		for _, candidate := range ecdsaHashes(pub.Curve) {
			digest := hashBytes(candidate.hash, data)
			if ecdsa.VerifyASN1(pub, digest, sig) {
				return candidate.name, true
			}
		}
		return "", false
	case *rsa.PublicKey:
		for _, candidate := range []struct {
			name string
			alg  x509.SignatureAlgorithm
		}{
			{"RSA-SHA256", x509.SHA256WithRSA},
			{"RSA-PSS-SHA256", x509.SHA256WithRSAPSS},
			{"RSA-SHA384", x509.SHA384WithRSA},
			{"RSA-SHA512", x509.SHA512WithRSA},
		} {
			if cert.CheckSignature(candidate.alg, data, sig) == nil {
				return candidate.name, true
			}
		}
		return "", false
	case ed25519.PublicKey:
		if ed25519.Verify(pub, data, sig) {
			return "Ed25519", true
		}
		return "", false
	default:
		return "", false
	}
}

type hashCandidate struct {
	name string
	hash crypto.Hash
}

func ecdsaHashes(curve elliptic.Curve) []hashCandidate {
	switch curve {
	case elliptic.P384():
		return []hashCandidate{
			{"ECDSA-SHA384", crypto.SHA384},
			{"ECDSA-SHA256", crypto.SHA256},
			{"ECDSA-SHA512", crypto.SHA512},
		}
	case elliptic.P521():
		return []hashCandidate{
			{"ECDSA-SHA512", crypto.SHA512},
			{"ECDSA-SHA384", crypto.SHA384},
			{"ECDSA-SHA256", crypto.SHA256},
		}
	default:
		return []hashCandidate{
			{"ECDSA-SHA256", crypto.SHA256},
			{"ECDSA-SHA384", crypto.SHA384},
			{"ECDSA-SHA512", crypto.SHA512},
		}
	}
}

func hashBytes(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA384:
		s := sha512.Sum384(data)
		return s[:]
	case crypto.SHA512:
		s := sha512.Sum512(data)
		return s[:]
	default:
		s := sha256.Sum256(data)
		return s[:]
	}
}

func decodeBase64Bytes(s string) ([]byte, bool) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(trimmed); err == nil {
			return b, true
		}
	}
	return nil, false
}

func checkSubjectMatch(targetDigest string, claimedDigests []string) string {
	if targetDigest == "" || len(claimedDigests) == 0 {
		return SubjectUnknown
	}
	normTarget := strings.ToLower(strings.TrimSpace(targetDigest))
	for _, d := range claimedDigests {
		if strings.ToLower(strings.TrimSpace(d)) == normTarget {
			return SubjectMatches
		}
	}
	return SubjectMismatch
}
