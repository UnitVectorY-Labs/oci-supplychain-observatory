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
	Label       string
	Type        string
	Meaning     string
	Value       string
	Depth       int
	Raw         string
	DecodedRows []PayloadRow
}

type BuildMaterial struct {
	URI     string
	Digests map[string]string
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
	} else if pred, ok := obj["predicate"].(string); ok && isStructuredJSON([]byte(pred)) {
		nestedSummary, nestedSignatures, nestedSBOM := SummarizeJSON([]byte(pred))
		out, signatures, isSBOM = append(out, nestedSummary...), append(signatures, nestedSignatures...), isSBOM || nestedSBOM
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

// ExtractBuildMaterials returns only materials explicitly published in SLSA-style
// provenance. It follows DSSE/base64 wrappers but never infers ancestry from image layers.
func ExtractBuildMaterials(raw []byte) []BuildMaterial {
	var doc any
	if json.Unmarshal(raw, &doc) != nil {
		if decoded, ok := DecodeBase64JSON(strings.TrimSpace(string(raw))); ok {
			return ExtractBuildMaterials(decoded)
		}
		return nil
	}
	var out []BuildMaterial
	collectBuildMaterials(doc, &out)
	return out
}

func collectBuildMaterials(v any, out *[]BuildMaterial) {
	switch x := v.(type) {
	case map[string]any:
		if predicateType, _ := x["predicateType"].(string); strings.Contains(strings.ToLower(predicateType), "slsa.dev/provenance") {
			collectMaterialFields(x["predicate"], out)
		}
		for key, value := range x {
			if key == "payload" || key == "Payload" {
				if encoded, ok := value.(string); ok {
					if decoded, ok := DecodeBase64JSON(strings.TrimSpace(encoded)); ok {
						*out = append(*out, ExtractBuildMaterials(decoded)...)
					}
				}
			}
			collectBuildMaterials(value, out)
		}
	case []any:
		for _, value := range x {
			collectBuildMaterials(value, out)
		}
	}
}

func collectMaterialFields(v any, out *[]BuildMaterial) {
	switch x := v.(type) {
	case string:
		if isStructuredJSON([]byte(x)) {
			var decoded any
			if json.Unmarshal([]byte(x), &decoded) == nil {
				collectMaterialFields(decoded, out)
			}
		}
	case map[string]any:
		for key, value := range x {
			if key == "materials" || key == "resolvedDependencies" {
				if items, ok := value.([]any); ok {
					for _, item := range items {
						if material, ok := buildMaterialFromValue(item); ok {
							*out = append(*out, material)
						}
					}
				}
			}
			collectMaterialFields(value, out)
		}
	case []any:
		for _, value := range x {
			collectMaterialFields(value, out)
		}
	}
}

func buildMaterialFromValue(v any) (BuildMaterial, bool) {
	obj, ok := v.(map[string]any)
	if !ok {
		return BuildMaterial{}, false
	}
	uri, _ := obj["uri"].(string)
	if uri == "" {
		uri, _ = obj["name"].(string)
	}
	digests := map[string]string{}
	if values, ok := obj["digest"].(map[string]any); ok {
		for algorithm, value := range values {
			if text, ok := value.(string); ok && text != "" {
				digests[algorithm] = text
			}
		}
	}
	return BuildMaterial{URI: uri, Digests: digests}, uri != ""
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
		*rows = append(*rows, payloadRow(key, x.Kind, "", depth, x.Raw, nested))
	case map[string]any:
		*rows = append(*rows, payloadRow(key, fmt.Sprintf("object (%d)", len(x)), "", depth, "", nil))
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			flattenRows(rows, k, x[k], depth+1, limit)
		}
	case []any:
		*rows = append(*rows, payloadRow(key, fmt.Sprintf("array (%d)", len(x)), "", depth, "", nil))
		for i, item := range x {
			flattenRows(rows, fmt.Sprintf("[%d]", i), item, depth+1, limit)
		}
	case string:
		*rows = append(*rows, payloadRow(key, "string", CompactString(x, 2000), depth, "", nil))
	case float64:
		*rows = append(*rows, payloadRow(key, "number", fmt.Sprint(x), depth, "", nil))
	case bool:
		*rows = append(*rows, payloadRow(key, "boolean", fmt.Sprint(x), depth, "", nil))
	case nil:
		*rows = append(*rows, payloadRow(key, "null", "", depth, "", nil))
	default:
		*rows = append(*rows, payloadRow(key, fmt.Sprintf("%T", v), fmt.Sprint(v), depth, "", nil))
	}
}

func payloadRow(key, typ, value string, depth int, raw string, decoded []PayloadRow) PayloadRow {
	label, meaning := FieldGuidance(key)
	return PayloadRow{Key: key, Label: label, Type: typ, Meaning: meaning, Value: value, Depth: depth, Raw: raw, DecodedRows: decoded}
}

// FieldGuidance gives common OCI supply-chain fields stable, educational labels.
// Unrecognized keys remain visible and are explicitly identified as schema-specific.
func FieldGuidance(key string) (string, string) {
	if key == "$" {
		return "Payload", "The complete published metadata document."
	}
	if strings.HasPrefix(key, "[") {
		return "Item " + strings.Trim(key, "[]"), "One entry in the surrounding list."
	}
	guidance := map[string][2]string{
		"_type":                  {"Statement schema", "Identifies the in-toto statement format used to bind claims to subjects."},
		"subject":                {"Attestation subjects", "Immutable artifact(s) that the attestation claims to describe; match these digests to the inspected image."},
		"predicateType":          {"Claim type", "URI naming the predicate schema and therefore how the claim body should be interpreted."},
		"predicate":              {"Claims", "Type-specific facts asserted by the attestation producer."},
		"payloadType":            {"Signed payload format", "DSSE domain-separation value identifying how the decoded payload is interpreted."},
		"payload":                {"Signed statement", "Base64-encoded statement covered by the DSSE signatures."},
		"signatures":             {"Envelope signatures", "Cryptographic signatures over the DSSE payload; presence alone does not mean this application verified them."},
		"sig":                    {"Signature bytes", "Base64-encoded cryptographic signature."},
		"keyid":                  {"Key hint", "Optional identifier that may help a verifier select a public key; it is not proof of identity."},
		"critical":               {"Signed Cosign claims", "Fields covered by a Cosign simple-signing signature."},
		"optional":               {"Optional Cosign claims", "Producer-supplied signed metadata whose semantics depend on the producer."},
		"docker-reference":       {"Repository identity", "Repository name asserted by the Cosign payload; the digest is the immutable identity."},
		"docker-manifest-digest": {"Signed image digest", "Immutable manifest digest that the Cosign payload claims was signed."},
		"spdxVersion":            {"SPDX version", "Version of the SPDX document model used by this SBOM."},
		"SPDXID":                 {"SPDX element ID", "Document-local identifier used to connect packages, files, and relationships."},
		"documentNamespace":      {"Document namespace", "Globally unique namespace that distinguishes this SPDX document and its element IDs."},
		"creationInfo":           {"SBOM creation", "Who or what created the SBOM and when it was produced."},
		"creators":               {"SBOM creators", "Organizations, people, or tools that created the SPDX document."},
		"created":                {"Created at", "Timestamp reported by the metadata producer."},
		"packages":               {"Packages", "Software package records observed or declared in the SBOM."},
		"relationships":          {"Relationships", "Explicit links such as DESCRIBES, CONTAINS, or DEPENDS_ON between SPDX elements."},
		"relationshipType":       {"Relationship kind", "SPDX-defined meaning of the link between two elements."},
		"licenseDeclared":        {"Declared license", "License expression stated by the package producer or SBOM author; not a legal conclusion."},
		"licenseConcluded":       {"Concluded license", "License expression concluded by the SBOM creator; NOASSERTION means no conclusion was made."},
		"downloadLocation":       {"Package source", "Location from which the package can be obtained; NOASSERTION means it was not established."},
		"filesAnalyzed":          {"Files analyzed", "Whether package-level license and verification fields were derived from analyzing package files."},
		"bomFormat":              {"SBOM format", "Identifies a CycloneDX bill of materials."},
		"specVersion":            {"Specification version", "Version of the document schema used by this payload."},
		"components":             {"Components", "Software components recorded in a CycloneDX SBOM."},
		"dependencies":           {"Dependency graph", "Declared dependency relationships between CycloneDX components."},
		"buildDefinition":        {"Build definition", "External inputs and parameters that describe what the builder was asked to build."},
		"buildType":              {"Build process type", "URI identifying the build workflow schema needed to interpret build parameters."},
		"externalParameters":     {"External build parameters", "Inputs controlled outside the builder and relevant to reproducing or evaluating the build."},
		"internalParameters":     {"Internal build parameters", "Builder-controlled settings; these may be redacted and are not normally policy inputs."},
		"resolvedDependencies":   {"Resolved build inputs", "Immutable dependencies available to the builder, which may include source and base container images."},
		"materials":              {"Build materials", "Inputs used by older SLSA provenance formats; entries may include source and base images."},
		"runDetails":             {"Build execution", "Who ran the build and execution-specific metadata about that run."},
		"builder":                {"Builder identity", "Identity of the build platform that produced the artifact, as asserted by provenance."},
		"invocationId":           {"Build invocation ID", "Identifier for this individual build execution."},
		"startedOn":              {"Build started", "Producer-reported start time for the build execution."},
		"finishedOn":             {"Build finished", "Producer-reported completion time for the build execution."},
		"byproducts":             {"Build byproducts", "Additional artifacts produced during the build that are not primary subjects."},
		"verificationMaterial":   {"Verification material", "Certificates and transparency-log evidence supplied for signature verification."},
		"certificate":            {"Signing certificate", "Certificate supplied to associate a signing key with an identity; trust requires cryptographic verification."},
		"tlogEntries":            {"Transparency-log entries", "Records intended to prove the signing event was logged; presence is not verification."},
		"digest":                 {"Content digest", "Cryptographic content identifier. Its meaning depends on the surrounding subject or material."},
		"uri":                    {"Resource URI", "Producer-supplied identifier for a subject or build input."},
		"name":                   {"Name", "Human-readable or schema-defined name; use the surrounding object to determine what it names."},
		"id":                     {"Identifier", "Schema-defined identity for the surrounding object."},
	}
	if entry, ok := guidance[key]; ok {
		return entry[0], entry[1]
	}
	return humanizeField(key), "Producer- or schema-defined field; interpret it using the surrounding predicate type."
}

func humanizeField(key string) string {
	var out []rune
	for i, r := range key {
		if i > 0 && r >= 'A' && r <= 'Z' {
			out = append(out, ' ')
		}
		out = append(out, r)
	}
	s := strings.ReplaceAll(string(out), "_", " ")
	if s == "" {
		return "Field"
	}
	return strings.ToUpper(s[:1]) + s[1:]
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
