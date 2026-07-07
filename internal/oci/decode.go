package oci

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"
)

type KV struct {
	Key   string
	Value string
}

type PayloadViews struct {
	Raw              string
	RawTruncated     bool
	Decoded          string
	DecodedChanged   bool
	DecodedJSON      bool
	DecodedTruncated bool
	Rows             []PayloadRow
	RowsTruncated    bool
}

type PayloadRow struct {
	Key         string
	Type        string
	Value       string
	Depth       int
	Raw         string
	DecodedRows []PayloadRow
}

func (r PayloadRow) DepthClass() string {
	if r.Depth < 0 {
		return "depth-0"
	}
	if r.Depth > 10 {
		return "depth-10"
	}
	return fmt.Sprintf("depth-%d", r.Depth)
}

type decodedValue struct {
	Kind  string
	Raw   string
	Value any
}

func ClassifyArtifact(artifactType, mediaType string, annotations map[string]string) string {
	var values []string
	for k, v := range annotations {
		values = append(values, k, v)
	}
	joined := strings.ToLower(artifactType + " " + mediaType + " " + strings.Join(values, " "))
	switch {
	case strings.Contains(joined, "sbom") || strings.Contains(joined, "spdx") || strings.Contains(joined, "cyclonedx"):
		return "SBOM"
	case strings.Contains(joined, "attestation") || strings.Contains(joined, "in-toto") || strings.Contains(joined, "intoto") || strings.Contains(joined, "predicate") || strings.Contains(joined, "slsa.dev"):
		return "Attestation"
	default:
		return "Signature"
	}
}

func SummarizeArtifactPayload(raw []byte, mediaType string) ([]KV, []KV, bool) {
	out := []KV{{"Payload media type", ValueOr(mediaType, "not provided")}}
	summary, signatures, isSBOM := SummarizeJSON(raw)
	out = append(out, summary...)
	if len(out) == 1 {
		out = append(out, KV{"Raw size", fmt.Sprintf("%d bytes", len(raw))})
	}
	return out, signatures, isSBOM
}

func SummarizeJSON(raw []byte) ([]KV, []KV, bool) {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		if decoded, ok := DecodeBase64JSON(strings.TrimSpace(string(raw))); ok {
			return SummarizeJSON(decoded)
		}
		return nil, nil, false
	}
	obj, _ := doc.(map[string]any)
	if obj == nil {
		return []KV{{"JSON", "valid JSON payload"}}, nil, false
	}
	var out []KV
	var signatures []KV
	isSBOM := false
	add := func(k, label string) {
		if v, ok := obj[k]; ok {
			out = append(out, KV{label, fmt.Sprint(v)})
		}
	}
	add("spdxVersion", "SPDX version")
	add("SPDXID", "SPDX ID")
	add("name", "Document name")
	add("documentNamespace", "Document namespace")
	add("bomFormat", "SBOM format")
	add("specVersion", "Spec version")
	add("serialNumber", "Serial number")
	add("predicateType", "Predicate type")
	if critical, ok := obj["critical"].(map[string]any); ok {
		if typ, ok := critical["type"].(string); ok {
			out = append(out, KV{"Cosign signature type", typ})
		}
		if identity, ok := critical["identity"].(map[string]any); ok {
			if dockerRef, ok := identity["docker-reference"].(string); ok {
				out = append(out, KV{"Signed Docker reference", dockerRef})
			}
		}
		if image, ok := critical["image"].(map[string]any); ok {
			if digest, ok := image["docker-manifest-digest"].(string); ok {
				out = append(out, KV{"Signed image digest", digest})
			}
		}
	}
	if predicateType, ok := obj["predicateType"].(string); ok && strings.Contains(strings.ToLower(predicateType), "spdx") {
		isSBOM = true
	}
	if sig, ok := obj["Base64Signature"].(string); ok {
		signatures = append(signatures, KV{"Cosign payload signature", CompactString(sig, 96)})
	}
	if payload, ok := obj["Payload"].(string); ok {
		signatures = append(signatures, KV{"Signed payload", "present"})
		nested, nestedSig, nestedSBOM := summarizeNested(payload)
		out, signatures, isSBOM = append(out, nested...), append(signatures, nestedSig...), isSBOM || nestedSBOM
	}
	if cert, ok := obj["Cert"].(map[string]any); ok {
		if raw, ok := cert["Raw"].(string); ok {
			out = append(out, CertificateSummary(raw)...)
		}
	}
	if envelope, ok := obj["dsseEnvelope"].(map[string]any); ok {
		if payload, ok := envelope["payload"].(string); ok {
			nested, nestedSig, nestedSBOM := summarizeNested(payload)
			out, signatures, isSBOM = append(out, nested...), append(signatures, nestedSig...), isSBOM || nestedSBOM
		}
		if payloadType, ok := envelope["payloadType"].(string); ok {
			out = append(out, KV{"Payload type", payloadType})
		}
	}
	if payload, ok := obj["payload"].(string); ok {
		signatures = append(signatures, KV{"DSSE payload", "present"})
		nested, nestedSig, nestedSBOM := summarizeNested(payload)
		out, signatures, isSBOM = append(out, nested...), append(signatures, nestedSig...), isSBOM || nestedSBOM
	}
	if sigs, ok := obj["signatures"].([]any); ok {
		out = append(out, KV{"DSSE signature count", fmt.Sprint(len(sigs))})
		for i, sigAny := range sigs {
			if sig, ok := sigAny.(map[string]any); ok {
				if val, ok := sig["sig"].(string); ok {
					signatures = append(signatures, KV{fmt.Sprintf("DSSE signature %d", i+1), CompactString(val, 96)})
				}
				if keyID, ok := sig["keyid"].(string); ok && keyID != "" {
					signatures = append(signatures, KV{fmt.Sprintf("DSSE signature %d key ID", i+1), keyID})
				}
			}
		}
	}
	if material, ok := obj["verificationMaterial"].(map[string]any); ok {
		if cert, ok := material["certificate"].(map[string]any); ok {
			if raw, ok := cert["rawBytes"].(string); ok {
				out = append(out, CertificateSummary(raw)...)
			}
		}
		if entries, ok := material["tlogEntries"].([]any); ok {
			out = append(out, KV{"Transparency log entries", fmt.Sprint(len(entries))})
		}
	}
	if pkgs, ok := obj["packages"].([]any); ok {
		out = append(out, KV{"Package count", fmt.Sprint(len(pkgs))})
		isSBOM = true
	}
	if comps, ok := obj["components"].([]any); ok {
		out = append(out, KV{"Component count", fmt.Sprint(len(comps))})
		isSBOM = true
	}
	if subject, ok := obj["subject"].([]any); ok {
		out = append(out, KV{"Subject count", fmt.Sprint(len(subject))})
	}
	if pred, ok := obj["predicate"].(map[string]any); ok {
		if rawPred, err := json.Marshal(pred); err == nil {
			nestedSummary, nestedSignatures, nestedSBOM := SummarizeJSON(rawPred)
			out, signatures, isSBOM = append(out, nestedSummary...), append(signatures, nestedSignatures...), isSBOM || nestedSBOM
		}
	}
	if len(out) == 0 {
		out = append(out, KV{"JSON", "valid JSON payload"})
	}
	return out, signatures, isSBOM
}

func summarizeNested(payload string) ([]KV, []KV, bool) {
	if decoded, ok := DecodeBase64JSON(payload); ok {
		return SummarizeJSON(decoded)
	}
	return nil, nil, false
}

func CertificateSummary(rawBase64 string) []KV {
	certText := strings.TrimSpace(rawBase64)
	var der []byte
	if block, _ := pem.Decode([]byte(certText)); block != nil {
		der = block.Bytes
	} else {
		decoded, err := base64.StdEncoding.DecodeString(certText)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(certText)
		}
		if err != nil {
			return []KV{{"Signing certificate", "present, but could not decode"}}
		}
		der = decoded
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return []KV{{"Signing certificate", "present, but could not parse"}}
	}
	out := []KV{{"Signing certificate", "present"}}
	if cert.Subject.String() != "" {
		out = append(out, KV{"Certificate subject", cert.Subject.String()})
	}
	if cert.Issuer.String() != "" {
		out = append(out, KV{"Certificate issuer", cert.Issuer.String()})
	}
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.4.1.57264.1.1" {
			var issuer string
			if _, err := asn1.Unmarshal(ext.Value, &issuer); err == nil && issuer != "" {
				out = append(out, KV{"OIDC issuer", issuer})
			}
		}
	}
	out = append(out, KV{"Certificate valid from", cert.NotBefore.Format(time.RFC3339)}, KV{"Certificate valid until", cert.NotAfter.Format(time.RFC3339)})
	return out
}

func DecodeBase64JSON(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b, err := enc.DecodeString(s)
		if err == nil && isStructuredJSON(b) {
			return b, true
		}
	}
	return nil, false
}

func BuildPayloadViews(raw []byte, max int64) PayloadViews {
	rawView, rawTruncated := Preview(raw, max)
	views := PayloadViews{Raw: rawView, RawTruncated: rawTruncated}

	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		if decoded, ok := DecodeBase64JSON(strings.TrimSpace(string(raw))); ok {
			var decodedDoc any
			if json.Unmarshal(decoded, &decodedDoc) == nil {
				expanded := decodedValue{Kind: "decoded base64 JSON", Raw: string(raw), Value: expandEncodedJSON("", decodedDoc)}
				views.Decoded, views.DecodedTruncated = prettyLimited(expanded, max)
				views.DecodedChanged = true
				views.DecodedJSON = true
				views.Rows, views.RowsTruncated = FlattenPayloadRows(expanded, 2000)
			}
		}
		return views
	}

	expanded := expandEncodedJSON("", doc)
	views.Decoded, views.DecodedTruncated = prettyLimited(expanded, max)
	views.DecodedChanged = !jsonEqual(doc, expanded)
	views.DecodedJSON = true
	views.Rows, views.RowsTruncated = FlattenPayloadRows(expanded, 2000)
	return views
}

func expandEncodedJSON(key string, v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, value := range x {
			out[k] = expandEncodedJSON(k, value)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, value := range x {
			out[i] = expandEncodedJSON("", value)
		}
		return out
	case string:
		trimmed := strings.TrimSpace(x)
		if strings.EqualFold(key, "rawBytes") {
			if cert := DecodeCertificateDetails(trimmed); cert != nil {
				return decodedValue{Kind: "decoded x509 certificate", Raw: x, Value: cert}
			}
		}
		if decoded, ok := DecodeBase64JSON(trimmed); ok {
			var decodedDoc any
			if json.Unmarshal(decoded, &decodedDoc) == nil {
				return decodedValue{Kind: "decoded base64 JSON", Raw: x, Value: expandEncodedJSON("", decodedDoc)}
			}
		}
		if isStructuredJSON([]byte(trimmed)) {
			var nested any
			if json.Unmarshal([]byte(trimmed), &nested) == nil {
				return decodedValue{Kind: "decoded JSON string", Raw: x, Value: expandEncodedJSON("", nested)}
			}
		}
		return x
	default:
		return v
	}
}

func isStructuredJSON(b []byte) bool {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return false
	}
	return json.Valid(trimmed)
}

func DecodeCertificateDetails(rawBase64 string) map[string]any {
	certText := strings.TrimSpace(rawBase64)
	var der []byte
	if block, _ := pem.Decode([]byte(certText)); block != nil {
		der = block.Bytes
	} else {
		decoded, err := base64.StdEncoding.DecodeString(certText)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(certText)
		}
		if err != nil {
			return nil
		}
		der = decoded
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}

	out := map[string]any{
		"serialNumber":       cert.SerialNumber.String(),
		"issuer":             cert.Issuer.String(),
		"subject":            cert.Subject.String(),
		"notBefore":          cert.NotBefore.Format(time.RFC3339),
		"notAfter":           cert.NotAfter.Format(time.RFC3339),
		"signatureAlgorithm": cert.SignatureAlgorithm.String(),
		"publicKeyAlgorithm": cert.PublicKeyAlgorithm.String(),
	}
	if len(cert.URIs) > 0 {
		values := make([]any, 0, len(cert.URIs))
		for _, u := range cert.URIs {
			values = append(values, u.String())
		}
		out["uriSANs"] = values
	}
	if len(cert.DNSNames) > 0 {
		values := make([]any, 0, len(cert.DNSNames))
		for _, name := range cert.DNSNames {
			values = append(values, name)
		}
		out["dnsSANs"] = values
	}
	if len(cert.EmailAddresses) > 0 {
		values := make([]any, 0, len(cert.EmailAddresses))
		for _, email := range cert.EmailAddresses {
			values = append(values, email)
		}
		out["emailSANs"] = values
	}
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.4.1.57264.1.1" {
			var issuer string
			if _, err := asn1.Unmarshal(ext.Value, &issuer); err == nil && issuer != "" {
				out["oidcIssuer"] = issuer
			}
		}
	}
	return out
}

func FlattenPayloadRows(v any, limit int) ([]PayloadRow, bool) {
	var rows []PayloadRow
	flattenRows(&rows, "$", v, 0, limit)
	return rows, len(rows) >= limit
}

func flattenRows(rows *[]PayloadRow, key string, v any, depth, limit int) {
	if len(*rows) >= limit {
		return
	}
	switch x := v.(type) {
	case decodedValue:
		nested := flattenPayloadRowsFromValue(x.Value, limit-len(*rows))
		*rows = append(*rows, PayloadRow{Key: key, Type: x.Kind, Raw: x.Raw, DecodedRows: nested, Depth: depth})
	case map[string]any:
		*rows = append(*rows, PayloadRow{Key: key, Type: fmt.Sprintf("object (%d)", len(x)), Depth: depth})
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			flattenRows(rows, k, x[k], depth+1, limit)
		}
	case []any:
		*rows = append(*rows, PayloadRow{Key: key, Type: fmt.Sprintf("array (%d)", len(x)), Depth: depth})
		for i, item := range x {
			flattenRows(rows, fmt.Sprintf("[%d]", i), item, depth+1, limit)
		}
	case string:
		*rows = append(*rows, PayloadRow{Key: key, Type: "string", Value: CompactString(x, 2000), Depth: depth})
	case float64:
		*rows = append(*rows, PayloadRow{Key: key, Type: "number", Value: fmt.Sprint(x), Depth: depth})
	case bool:
		*rows = append(*rows, PayloadRow{Key: key, Type: "boolean", Value: fmt.Sprint(x), Depth: depth})
	case nil:
		*rows = append(*rows, PayloadRow{Key: key, Type: "null", Depth: depth})
	default:
		*rows = append(*rows, PayloadRow{Key: key, Type: fmt.Sprintf("%T", v), Value: fmt.Sprint(v), Depth: depth})
	}
}

func flattenPayloadRowsFromValue(v any, limit int) []PayloadRow {
	var rows []PayloadRow
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			flattenRows(&rows, k, x[k], 0, limit)
		}
	case []any:
		for i, item := range x {
			flattenRows(&rows, fmt.Sprintf("[%d]", i), item, 0, limit)
		}
	default:
		flattenRows(&rows, "value", v, 0, limit)
	}
	return rows
}

func prettyLimited(v any, max int64) (string, bool) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprint(v), false
	}
	truncated := int64(len(b)) > max
	if truncated {
		b = b[:max]
	}
	return string(b), truncated
}

func jsonEqual(a, b any) bool {
	ab, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bb, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}

func Preview(raw []byte, max int64) (string, bool) {
	truncated := int64(len(raw)) > max
	if truncated {
		raw = raw[:max]
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, raw, "", "  ") == nil {
		return pretty.String(), truncated
	}
	return string(raw), truncated
}

func CompactString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max < 8 {
		return s[:max]
	}
	head := max/2 - 2
	tail := max - head - 5
	return s[:head] + " ... " + s[len(s)-tail:]
}

func DigestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func MakeID(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:12])
}

func LegacyCosignTag(digest, suffix string) string {
	return strings.ReplaceAll(digest, ":", "-") + suffix
}

func ValueOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
