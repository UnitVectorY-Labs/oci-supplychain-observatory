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
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type KV struct {
	Key   string
	Value string
}

func (kv KV) Link() string {
	parsed, err := url.Parse(strings.TrimSpace(kv.Value))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return ""
	}
	return parsed.String()
}

type CertificateInfo struct {
	SerialNumber       string
	Subject            string
	Issuer             string
	NotBefore          time.Time
	NotAfter           time.Time
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	URIs               []string
	Emails             []string
	DNSNames           []string
	OIDCIssuer         string
	BuildSignerURI     string
	BuildConfigURI     string
	SourceRepoURI      string
	SourceRepoDigest   string
	SourceRepoRef      string
	WorkflowName       string
	WorkflowRepo       string
	WorkflowRef        string
	WorkflowTrigger    string
	RunnerEnvironment  string
}

func (c *CertificateInfo) PrimaryIdentity() string {
	if c == nil {
		return ""
	}
	if len(c.URIs) > 0 {
		return c.URIs[0]
	}
	if len(c.Emails) > 0 {
		return c.Emails[0]
	}
	if len(c.DNSNames) > 0 {
		return c.DNSNames[0]
	}
	if c.BuildSignerURI != "" {
		return c.BuildSignerURI
	}
	return c.Subject
}

type RekorEntry struct {
	LogIndex       string
	IntegratedTime time.Time
	LogID          string
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

func (r PayloadRow) DisplayKey() string {
	if strings.HasPrefix(r.Key, "[") && strings.HasSuffix(r.Key, "]") {
		return "Item"
	}
	if r.Key == "$" {
		return "Document"
	}
	return r.Key
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
	case strings.EqualFold(strings.TrimSpace(mediaType), MediaDSSEEnvelope):
		return "Attestation"
	case strings.EqualFold(strings.TrimSpace(mediaType), MediaCosignSimpleSigning) || strings.Contains(joined, "cosign") || strings.Contains(joined, "signature") || strings.Contains(joined, "sigstore"):
		return "Signature"
	default:
		return "Other metadata"
	}
}

func IsMetadataLayer(mediaType string) bool {
	mt := strings.ToLower(strings.TrimSpace(mediaType))
	return mt == MediaCosignSimpleSigning ||
		mt == MediaDSSEEnvelope ||
		strings.Contains(mt, "spdx") ||
		strings.Contains(mt, "cyclonedx") ||
		strings.Contains(mt, "in-toto") ||
		strings.Contains(mt, "intoto") ||
		strings.Contains(mt, "attestation") ||
		strings.HasSuffix(mt, "+json") ||
		mt == "application/json" ||
		mt == "text/json"
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
	// Some producers put the in-toto statement directly in the envelope rather
	// than base64 encoding it. Accept both forms so the useful predicate data is
	// visible regardless of which container builder produced it.
	trimmed := strings.TrimSpace(payload)
	if isStructuredJSON([]byte(trimmed)) {
		return SummarizeJSON([]byte(trimmed))
	}
	return nil, nil, false
}

func ParseX509Certificate(raw string) (*x509.Certificate, error) {
	certText := strings.TrimSpace(raw)
	if certText == "" {
		return nil, fmt.Errorf("empty certificate")
	}
	var der []byte
	if block, _ := pem.Decode([]byte(certText)); block != nil {
		der = block.Bytes
	} else {
		var err error
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if decoded, decErr := enc.DecodeString(certText); decErr == nil {
				der = decoded
				err = nil
				break
			} else {
				err = decErr
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return x509.ParseCertificate(der)
}

func ParseCertificate(raw string) (*CertificateInfo, bool) {
	cert, err := ParseX509Certificate(raw)
	if err != nil {
		return nil, false
	}
	info := &CertificateInfo{
		SerialNumber:       cert.SerialNumber.String(),
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		NotBefore:          cert.NotBefore.UTC(),
		NotAfter:           cert.NotAfter.UTC(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
	}
	for _, u := range cert.URIs {
		info.URIs = append(info.URIs, u.String())
	}
	info.Emails = append(info.Emails, cert.EmailAddresses...)
	info.DNSNames = append(info.DNSNames, cert.DNSNames...)

	for _, ext := range cert.Extensions {
		val := decodeFulcioExtensionValue(ext.Value)
		if val == "" {
			continue
		}
		switch ext.Id.String() {
		case "1.3.6.1.4.1.57264.1.1":
			if info.OIDCIssuer == "" {
				info.OIDCIssuer = val
			}
		case "1.3.6.1.4.1.57264.1.8":
			info.OIDCIssuer = val
		case "1.3.6.1.4.1.57264.1.2":
			info.WorkflowTrigger = val
		case "1.3.6.1.4.1.57264.1.4":
			info.WorkflowName = val
		case "1.3.6.1.4.1.57264.1.5":
			info.WorkflowRepo = val
		case "1.3.6.1.4.1.57264.1.6":
			info.WorkflowRef = val
		case "1.3.6.1.4.1.57264.1.9":
			info.BuildSignerURI = val
		case "1.3.6.1.4.1.57264.1.12":
			info.SourceRepoURI = val
		case "1.3.6.1.4.1.57264.1.13":
			info.SourceRepoDigest = val
		case "1.3.6.1.4.1.57264.1.14":
			info.SourceRepoRef = val
		case "1.3.6.1.4.1.57264.1.18":
			info.RunnerEnvironment = val
		case "1.3.6.1.4.1.57264.1.20":
			info.BuildConfigURI = val
		}
	}
	return info, true
}

func decodeFulcioExtensionValue(raw []byte) string {
	var str string
	if rest, err := asn1.Unmarshal(raw, &str); err == nil && len(rest) == 0 && strings.TrimSpace(str) != "" {
		return strings.TrimSpace(str)
	}
	// Fulcio v1 extensions (1.1..1.6) were historically raw UTF-8 bytes without ASN.1 string wrapper.
	text := strings.TrimSpace(string(raw))
	for _, r := range text {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return text
}

func CertificateSummary(rawBase64 string) []KV {
	info, ok := ParseCertificate(rawBase64)
	if !ok {
		return []KV{{"Signing certificate", "present, but could not parse"}}
	}
	out := []KV{{"Signing certificate", "present"}}
	if id := info.PrimaryIdentity(); id != "" {
		out = append(out, KV{"Certificate identity", id})
	}
	if info.Subject != "" {
		out = append(out, KV{"Certificate subject", info.Subject})
	}
	if info.Issuer != "" {
		out = append(out, KV{"Certificate issuer", info.Issuer})
	}
	if info.OIDCIssuer != "" {
		out = append(out, KV{"OIDC issuer", info.OIDCIssuer})
	}
	if info.SourceRepoURI != "" {
		out = append(out, KV{"Certificate source repository", info.SourceRepoURI})
	}
	if info.WorkflowRef != "" {
		out = append(out, KV{"Certificate workflow ref", info.WorkflowRef})
	}
	if info.RunnerEnvironment != "" {
		out = append(out, KV{"Certificate runner environment", info.RunnerEnvironment})
	}
	out = append(out,
		KV{"Certificate valid from", info.NotBefore.Format(time.RFC3339)},
		KV{"Certificate valid until", info.NotAfter.Format(time.RFC3339)},
	)
	return out
}

func ExtractRekorInfo(raw []byte, annotations map[string]string) *RekorEntry {
	var doc map[string]any
	if len(raw) > 0 && json.Unmarshal(raw, &doc) == nil {
		if material, ok := doc["verificationMaterial"].(map[string]any); ok {
			if entries, ok := material["tlogEntries"].([]any); ok && len(entries) > 0 {
				if entry, ok := entries[0].(map[string]any); ok {
					return parseRekorMap(entry)
				}
			}
		}
	}
	for k, v := range annotations {
		if strings.Contains(strings.ToLower(k), "bundle") && strings.TrimSpace(v) != "" {
			var bundle map[string]any
			if json.Unmarshal([]byte(v), &bundle) == nil {
				if payload, ok := bundle["Payload"].(map[string]any); ok {
					if entry := parseRekorMap(payload); entry != nil {
						return entry
					}
				}
				if entry := parseRekorMap(bundle); entry != nil {
					return entry
				}
			}
		}
	}
	return nil
}

func parseRekorMap(m map[string]any) *RekorEntry {
	var entry RekorEntry
	if idx, ok := m["logIndex"]; ok {
		entry.LogIndex = formatJSONNumber(idx)
	}
	if rawTime, ok := m["integratedTime"]; ok {
		if sec, err := parseUnixSeconds(rawTime); err == nil && sec > 0 {
			entry.IntegratedTime = time.Unix(sec, 0).UTC()
		}
	}
	if id, ok := m["logID"].(string); ok {
		entry.LogID = id
	} else if logIDMap, ok := m["logId"].(map[string]any); ok {
		if keyID, ok := logIDMap["keyId"].(string); ok {
			entry.LogID = keyID
		}
	}
	if entry.LogIndex == "" && entry.IntegratedTime.IsZero() && entry.LogID == "" {
		return nil
	}
	return &entry
}

func formatJSONNumber(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strconv.FormatInt(int64(x), 10)
	default:
		return fmt.Sprint(v)
	}
}

func parseUnixSeconds(v any) (int64, error) {
	switch x := v.(type) {
	case float64:
		return int64(x), nil
	case string:
		return strconv.ParseInt(strings.TrimSpace(x), 10, 64)
	default:
		return 0, fmt.Errorf("unsupported time")
	}
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
	info, ok := ParseCertificate(rawBase64)
	if !ok {
		return nil
	}

	out := map[string]any{
		"serialNumber":       info.SerialNumber,
		"issuer":             info.Issuer,
		"subject":            info.Subject,
		"notBefore":          info.NotBefore.Format(time.RFC3339),
		"notAfter":           info.NotAfter.Format(time.RFC3339),
		"signatureAlgorithm": info.SignatureAlgorithm,
		"publicKeyAlgorithm": info.PublicKeyAlgorithm,
	}
	if len(info.URIs) > 0 {
		values := make([]any, 0, len(info.URIs))
		for _, u := range info.URIs {
			values = append(values, u)
		}
		out["uriSANs"] = values
	}
	if len(info.DNSNames) > 0 {
		values := make([]any, 0, len(info.DNSNames))
		for _, name := range info.DNSNames {
			values = append(values, name)
		}
		out["dnsSANs"] = values
	}
	if len(info.Emails) > 0 {
		values := make([]any, 0, len(info.Emails))
		for _, email := range info.Emails {
			values = append(values, email)
		}
		out["emailSANs"] = values
	}
	if info.OIDCIssuer != "" {
		out["oidcIssuer"] = info.OIDCIssuer
	}
	if info.BuildSignerURI != "" {
		out["buildSignerURI"] = info.BuildSignerURI
	}
	if info.SourceRepoURI != "" {
		out["sourceRepositoryURI"] = info.SourceRepoURI
	}
	if info.SourceRepoRef != "" {
		out["sourceRepositoryRef"] = info.SourceRepoRef
	}
	if info.RunnerEnvironment != "" {
		out["runnerEnvironment"] = info.RunnerEnvironment
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
