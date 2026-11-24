package inspect

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/oci"
)

const (
	maxRenderedComponents  = 200
	maxTraversedComponents = 10000
)

func analyzeArtifact(artifact *Artifact) {
	doc, ok := decodeArtifactDocument(artifact.Raw)
	if !ok {
		artifact.Purpose = artifact.Type
		return
	}

	predicateType := stringAt(doc, "predicateType")
	predicate, _ := doc["predicate"].(map[string]any)
	content := doc
	if predicate != nil {
		content = predicate
	}

	artifact.ClaimedDigests = extractClaimedDigests(doc)

	switch {
	case isSPDX(content, predicateType):
		artifact.Purpose = "SPDX SBOM"
		artifact.Type = "SBOM attestation"
		artifact.Facts, artifact.Components, artifact.ComponentsTruncated, artifact.SBOM = analyzeSPDX(content, doc)
	case isCycloneDX(content, predicateType):
		artifact.Purpose = "CycloneDX SBOM"
		artifact.Type = "SBOM attestation"
		artifact.Facts, artifact.Components, artifact.ComponentsTruncated, artifact.SBOM = analyzeCycloneDX(content, doc)
	case strings.Contains(strings.ToLower(predicateType), "slsa") || content["buildDefinition"] != nil || content["builder"] != nil:
		artifact.Purpose = "SLSA build provenance"
		artifact.Type = "Attestation"
		artifact.Facts, artifact.Provenance = analyzeProvenance(doc, content, artifact.TargetDigest)
	case doc["critical"] != nil:
		artifact.Purpose = "Container image signature"
		artifact.Type = "Signature"
		artifact.Facts, artifact.Signature = analyzeSignature(doc)
	default:
		artifact.Purpose = friendlyPredicatePurpose(predicateType, artifact.Type)
		if predicateType != "" {
			artifact.Facts = append(artifact.Facts, oci.KV{Key: "Predicate", Value: predicateType})
		}
	}
}

func friendlyPredicatePurpose(predicateType, fallback string) string {
	lower := strings.ToLower(predicateType)
	switch {
	case strings.Contains(lower, "apko.dev"):
		return "apko image configuration"
	case strings.Contains(lower, "vuln") || strings.Contains(lower, "cosign.sigstore.dev/attestation/vuln"):
		return "Vulnerability scan attestation"
	case strings.Contains(lower, "openvex") || strings.Contains(lower, "vex"):
		return "VEX attestation"
	case strings.Contains(lower, "scai"):
		return "SCAI attribute assertion"
	case strings.Contains(lower, "sigstore.dev/cosign"):
		return "Cosign attestation"
	case fallback != "":
		return fallback
	default:
		return "Published metadata"
	}
}

func extractClaimedDigests(doc map[string]any) []string {
	var digests []string
	if subjects, ok := doc["subject"].([]any); ok {
		for _, item := range subjects {
			sub, _ := item.(map[string]any)
			if dmap, ok := sub["digest"].(map[string]any); ok {
				for algo, val := range dmap {
					if s, ok := val.(string); ok && strings.TrimSpace(s) != "" {
						digests = append(digests, strings.ToLower(algo)+":"+strings.TrimSpace(s))
					}
				}
			}
		}
	}
	if critical, ok := doc["critical"].(map[string]any); ok {
		if d := nestedString(critical, "image", "docker-manifest-digest"); d != "" {
			digests = append(digests, strings.TrimSpace(d))
		}
	}
	return digests
}

func decodeArtifactDocument(raw []byte) (map[string]any, bool) {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return nil, false
	}
	// Cosign and registry builders have emitted several envelope variants over
	// time: Payload vs payload, DSSE envelopes, and either raw or base64 JSON.
	// Walk those envelopes until we reach the statement/predicate document.
	for depth := 0; depth < 8; depth++ {
		var payload string
		for _, path := range [][]string{{"dsseEnvelope", "payload"}, {"payload"}, {"Payload"}} {
			if value := nestedString(doc, path...); value != "" {
				payload = value
				break
			}
		}
		if payload == "" {
			return normalizePredicate(doc), true
		}
		decoded, ok := decodeBase64(payload)
		if !ok {
			decoded = []byte(strings.TrimSpace(payload))
			if !json.Valid(decoded) {
				return normalizePredicate(doc), true
			}
		}
		var nested map[string]any
		if json.Unmarshal(decoded, &nested) != nil {
			return normalizePredicate(doc), true
		}
		doc = nested
	}
	return normalizePredicate(doc), true
}

func decodeBase64(value string) ([]byte, bool) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(strings.TrimSpace(value))
		if err == nil && json.Valid(decoded) {
			return decoded, true
		}
	}
	return nil, false
}

func normalizePredicate(doc map[string]any) map[string]any {
	if encoded, ok := doc["predicate"].(string); ok {
		if predicate := decodeNestedObject(encoded); predicate != nil {
			doc["predicate"] = predicate
		}
	}
	return doc
}

func decodeNestedObject(value string) map[string]any {
	trimmed := strings.TrimSpace(value)
	if decoded, ok := decodeBase64(trimmed); ok {
		trimmed = string(decoded)
	}
	var nested map[string]any
	if json.Unmarshal([]byte(trimmed), &nested) == nil {
		return nested
	}
	return nil
}

func isSPDX(doc map[string]any, predicateType string) bool {
	return stringAt(doc, "spdxVersion") != "" || strings.Contains(strings.ToLower(predicateType), "spdx")
}

func isCycloneDX(doc map[string]any, predicateType string) bool {
	return strings.EqualFold(stringAt(doc, "bomFormat"), "CycloneDX") || strings.Contains(strings.ToLower(predicateType), "cyclonedx")
}

func analyzeSPDX(doc, statement map[string]any) ([]oci.KV, []Component, bool, *SBOMDetail) {
	format := valueOr(stringAt(doc, "spdxVersion"), "SPDX")
	facts := []oci.KV{{Key: "Format", Value: format}}
	docName := stringAt(doc, "name")
	appendFact(&facts, "Document", docName)
	appendSubjects(&facts, statement)

	detail := &SBOMDetail{
		Format:            format,
		DocumentName:      docName,
		RelationshipLabel: "Relationships",
	}
	if creation, ok := doc["creationInfo"].(map[string]any); ok {
		createdStr := stringAt(creation, "created")
		appendFact(&facts, "Created", createdStr)
		if t, err := time.Parse(time.RFC3339Nano, createdStr); err == nil {
			detail.Created = t.UTC()
		}
		if creators := stringSlice(creation["creators"]); len(creators) > 0 {
			detail.Creators = creators
			appendFact(&facts, "Generated by", strings.Join(creators, ", "))
		}
	}
	packages, hasPackages := doc["packages"].([]any)
	if !hasPackages {
		detail.UnsupportedInventory = true
		return append(facts, oci.KV{Key: "Inventory", Value: "No supported package inventory in this document"}), nil, false, detail
	}
	relationships, _ := doc["relationships"].([]any)
	detail.RelationshipCount = len(relationships)
	detail.TotalComponents = len(packages)
	detail.TotalComponentsLabel = fmt.Sprint(len(packages))
	if len(packages) > maxTraversedComponents {
		detail.ComponentsCapped = true
	}

	facts = append(facts,
		oci.KV{Key: "Components", Value: fmt.Sprint(len(packages))},
		oci.KV{Key: "Relationships", Value: fmt.Sprint(len(relationships))},
	)

	allComponents := make([]Component, 0, min(len(packages), maxTraversedComponents))
	ecoCounts := map[string]int{}
	licCounts := map[string]int{}

	for i, item := range packages {
		if i >= maxTraversedComponents {
			break
		}
		pkg, ok := item.(map[string]any)
		if !ok {
			continue
		}
		license := cleanNoAssertion(stringAt(pkg, "licenseConcluded"))
		if license == "" {
			license = cleanNoAssertion(stringAt(pkg, "licenseDeclared"))
		}
		component := Component{
			Name:     stringAt(pkg, "name"),
			Version:  stringAt(pkg, "versionInfo"),
			Supplier: cleanNoAssertion(stringAt(pkg, "supplier")),
			License:  license,
		}
		if refs, ok := pkg["externalRefs"].([]any); ok {
			for _, refAny := range refs {
				ref, _ := refAny.(map[string]any)
				if strings.EqualFold(stringAt(ref, "referenceType"), "purl") {
					component.PURL = stringAt(ref, "referenceLocator")
					component.Ecosystem, component.Platform = purlDetails(component.PURL)
					break
				}
			}
		}
		allComponents = append(allComponents, component)
		if component.Ecosystem != "" {
			ecoCounts[component.Ecosystem]++
		}
		if component.License != "" {
			licCounts[component.License]++
		}
	}
	detail.AllComponents = allComponents
	detail.Ecosystems = sortedFacets(ecoCounts)
	detail.Licenses = sortedFacets(licCounts)

	rendered := allComponents
	if len(rendered) > maxRenderedComponents {
		rendered = rendered[:maxRenderedComponents]
	}
	return facts, rendered, len(packages) > maxRenderedComponents, detail
}

func analyzeCycloneDX(doc, statement map[string]any) ([]oci.KV, []Component, bool, *SBOMDetail) {
	format := strings.TrimSpace("CycloneDX " + stringAt(doc, "specVersion"))
	facts := []oci.KV{{Key: "Format", Value: format}}
	appendSubjects(&facts, statement)

	detail := &SBOMDetail{
		Format:            format,
		RelationshipLabel: "Dependencies",
	}
	if metadata, ok := doc["metadata"].(map[string]any); ok {
		ts := stringAt(metadata, "timestamp")
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			detail.Created = t.UTC()
		}
		if comp, ok := metadata["component"].(map[string]any); ok {
			detail.DocumentName = stringAt(comp, "name")
		}
		detail.Creators = extractCycloneDXTools(metadata)
	}

	componentsRaw, hasComponents := doc["components"].([]any)
	if !hasComponents {
		detail.UnsupportedInventory = true
		return append(facts, oci.KV{Key: "Inventory", Value: "No supported package inventory in this document"}), nil, false, detail
	}
	dependencies, _ := doc["dependencies"].([]any)
	componentCount := countCycloneDXComponents(componentsRaw, maxTraversedComponents)
	componentCountLabel := fmt.Sprint(componentCount)
	if componentCount == maxTraversedComponents {
		componentCountLabel += "+"
		detail.ComponentsCapped = true
	}
	detail.TotalComponents = componentCount
	detail.TotalComponentsLabel = componentCountLabel
	detail.RelationshipCount = len(dependencies)

	facts = append(facts,
		oci.KV{Key: "Components", Value: componentCountLabel},
		oci.KV{Key: "Dependencies", Value: fmt.Sprint(len(dependencies))},
	)
	if metadata, ok := doc["metadata"].(map[string]any); ok {
		appendFact(&facts, "Created", stringAt(metadata, "timestamp"))
	}

	allComponents := make([]Component, 0, min(componentCount, maxTraversedComponents))
	ecoCounts := map[string]int{}
	licCounts := map[string]int{}

	var visit func([]any)
	visited := 0
	visit = func(entries []any) {
		for _, item := range entries {
			if visited >= maxTraversedComponents {
				return
			}
			visited++
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			component := Component{
				Name:     stringAt(entry, "name"),
				Version:  stringAt(entry, "version"),
				Supplier: cleanNoAssertion(nestedString(entry, "supplier", "name")),
				PURL:     stringAt(entry, "purl"),
				License:  cleanNoAssertion(cycloneDXLicense(entry["licenses"])),
			}
			component.Ecosystem, component.Platform = purlDetails(component.PURL)
			allComponents = append(allComponents, component)
			if component.Ecosystem != "" {
				ecoCounts[component.Ecosystem]++
			}
			if component.License != "" {
				licCounts[component.License]++
			}
			if nested, ok := entry["components"].([]any); ok {
				visit(nested)
			}
		}
	}
	visit(componentsRaw)

	detail.AllComponents = allComponents
	detail.Ecosystems = sortedFacets(ecoCounts)
	detail.Licenses = sortedFacets(licCounts)

	rendered := allComponents
	if len(rendered) > maxRenderedComponents {
		rendered = rendered[:maxRenderedComponents]
	}
	return facts, rendered, componentCount > maxRenderedComponents || visited >= maxTraversedComponents, detail
}

func extractCycloneDXTools(metadata map[string]any) []string {
	var tools []string
	switch raw := metadata["tools"].(type) {
	case []any:
		for _, item := range raw {
			if m, ok := item.(map[string]any); ok {
				name := strings.TrimSpace(stringAt(m, "name") + " " + stringAt(m, "version"))
				if name != "" {
					tools = append(tools, name)
				}
			}
		}
	case map[string]any:
		if comps, ok := raw["components"].([]any); ok {
			for _, item := range comps {
				if m, ok := item.(map[string]any); ok {
					name := strings.TrimSpace(stringAt(m, "name") + " " + stringAt(m, "version"))
					if name != "" {
						tools = append(tools, name)
					}
				}
			}
		}
	}
	return tools
}

func cleanNoAssertion(s string) string {
	s = strings.TrimSpace(s)
	if strings.EqualFold(s, "NOASSERTION") || strings.EqualFold(s, "NONE") {
		return ""
	}
	return s
}

func sortedFacets(counts map[string]int) []FacetCount {
	if len(counts) == 0 {
		return nil
	}
	out := make([]FacetCount, 0, len(counts))
	for k, v := range counts {
		out = append(out, FacetCount{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func countCycloneDXComponents(entries []any, limit int) int {
	count := 0
	var visit func([]any)
	visit = func(items []any) {
		for _, item := range items {
			if count >= limit {
				return
			}
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			count++
			if nested, ok := entry["components"].([]any); ok {
				visit(nested)
			}
		}
	}
	visit(entries)
	return count
}

func cycloneDXLicense(raw any) string {
	licenses, _ := raw.([]any)
	for _, item := range licenses {
		entry, _ := item.(map[string]any)
		if license, ok := entry["license"].(map[string]any); ok {
			if value := valueOr(stringAt(license, "id"), stringAt(license, "name")); value != "" {
				return value
			}
		}
		if expression := stringAt(entry, "expression"); expression != "" {
			return expression
		}
	}
	return ""
}

func analyzeProvenance(statement, predicate map[string]any, targetDigest string) ([]oci.KV, *ProvenanceDetail) {
	var facts []oci.KV
	appendSubjects(&facts, statement)
	predicateType := stringAt(statement, "predicateType")
	appendFact(&facts, "Predicate", predicateType)

	detail := &ProvenanceDetail{
		SLSAVersion: slsaVersionLabel(predicateType, predicate),
		Subjects:    extractSubjectClaims(statement, targetDigest),
	}

	buildDefinition, _ := predicate["buildDefinition"].(map[string]any)
	if buildDefinition != nil {
		bt := stringAt(buildDefinition, "buildType")
		detail.BuildType = bt
		appendFact(&facts, "Build type", bt)

		external, _ := buildDefinition["externalParameters"].(map[string]any)
		wfRepo := nestedString(external, "workflow", "repository")
		wfRef := nestedString(external, "workflow", "ref")
		wfPath := nestedString(external, "workflow", "path")
		dfPath := nestedString(external, "configSource", "path")
		if dfPath == "" {
			dfPath = nestedString(external, "request", "frontend", "attrs", "filename")
		}
		appendFact(&facts, "Source", wfRepo)
		appendFact(&facts, "Source ref", wfRef)
		appendFact(&facts, "Workflow", wfPath)
		appendFact(&facts, "Dockerfile", dfPath)

		setIfEmpty(&detail.SourceRepo, wfRepo)
		setIfEmpty(&detail.SourceRef, wfRef)
		setIfEmpty(&detail.Workflow, wfPath)
		setIfEmpty(&detail.Dockerfile, dfPath)

		// BuildKit / GitHub Actions externalParameters variants.
		if cfgURI := nestedString(external, "configSource", "uri"); cfgURI != "" {
			setIfEmpty(&detail.SourceRepo, cfgURI)
			appendFact(&facts, "Source", cfgURI)
		}
		if entryPoint := nestedString(external, "configSource", "entryPoint"); entryPoint != "" {
			setIfEmpty(&detail.Workflow, entryPoint)
		}
		if rootArgs, ok := nestedMap(external, "request", "root", "request", "args"); ok {
			src := stringAt(rootArgs, "vcs:source")
			rev := stringAt(rootArgs, "vcs:revision")
			appendFact(&facts, "Source", src)
			appendFact(&facts, "Commit", rev)
			setIfEmpty(&detail.SourceRepo, src)
			setIfEmpty(&detail.Commit, rev)
		}
		if deps, ok := buildDefinition["resolvedDependencies"].([]any); ok {
			detail.ResolvedInputCount = len(deps)
			facts = append(facts, oci.KV{Key: "Resolved inputs", Value: fmt.Sprint(len(deps))})
			for _, depAny := range deps {
				dep, _ := depAny.(map[string]any)
				uri := stringAt(dep, "uri")
				digestMap, _ := dep["digest"].(map[string]any)
				digestStr := firstMapValue(digestMap)
				if uri != "" {
					detail.Materials = append(detail.Materials, ProvenanceMaterial{
						URI:    uri,
						Digest: digestStr,
						Kind:   classifyMaterialKind(uri),
					})
				}
				if strings.HasPrefix(uri, "git+") {
					appendFact(&facts, "Source material", uri)
					setIfEmpty(&detail.SourceRepo, strings.TrimPrefix(uri, "git+"))
					if digestStr != "" {
						appendFact(&facts, "Commit", digestStr)
						setIfEmpty(&detail.Commit, digestStr)
					}
				}
			}
		}
	}
	if builder, ok := nestedMap(predicate, "runDetails", "builder"); ok {
		bID := stringAt(builder, "id")
		appendFact(&facts, "Builder", bID)
		setIfEmpty(&detail.Builder, bID)
	}
	if metadata, ok := nestedMap(predicate, "runDetails", "metadata"); ok {
		inv := stringAt(metadata, "invocationId")
		started := stringAt(metadata, "startedOn")
		finished := stringAt(metadata, "finishedOn")
		appendFact(&facts, "Build run", inv)
		appendFact(&facts, "Started", started)
		appendFact(&facts, "Finished", finished)
		setIfEmpty(&detail.InvocationID, inv)
		if t, err := time.Parse(time.RFC3339Nano, started); err == nil {
			detail.StartedAt = t.UTC()
		}
		if t, err := time.Parse(time.RFC3339Nano, finished); err == nil {
			detail.FinishedAt = t.UTC()
		}
	}

	// SLSA v0.2 fields.
	if builder, ok := predicate["builder"].(map[string]any); ok {
		bID := stringAt(builder, "id")
		appendFact(&facts, "Builder", bID)
		setIfEmpty(&detail.Builder, bID)
	}
	if bt := stringAt(predicate, "buildType"); bt != "" {
		appendFact(&facts, "Build type", bt)
		setIfEmpty(&detail.BuildType, bt)
	}
	if metadata, ok := predicate["metadata"].(map[string]any); ok {
		inv := stringAt(metadata, "invocationId")
		started := stringAt(metadata, "buildStartedOn")
		finished := stringAt(metadata, "buildFinishedOn")
		appendFact(&facts, "Build run", inv)
		appendFact(&facts, "Started", started)
		appendFact(&facts, "Finished", finished)
		setIfEmpty(&detail.InvocationID, inv)
		if detail.StartedAt.IsZero() {
			if t, err := time.Parse(time.RFC3339Nano, started); err == nil {
				detail.StartedAt = t.UTC()
			}
		}
		if detail.FinishedAt.IsZero() {
			if t, err := time.Parse(time.RFC3339Nano, finished); err == nil {
				detail.FinishedAt = t.UTC()
			}
		}
	}
	if invocation, ok := predicate["invocation"].(map[string]any); ok {
		if source, ok := invocation["configSource"].(map[string]any); ok {
			src := stringAt(source, "uri")
			appendFact(&facts, "Source", src)
			setIfEmpty(&detail.SourceRepo, src)
			if entry := stringAt(source, "entryPoint"); entry != "" {
				setIfEmpty(&detail.Workflow, entry)
			}
			if digest, ok := source["digest"].(map[string]any); ok {
				refVal := firstMapValue(digest)
				appendFact(&facts, "Source ref", refVal)
				setIfEmpty(&detail.Commit, refVal)
			}
		}
	}
	if materials, ok := predicate["materials"].([]any); ok {
		if detail.ResolvedInputCount == 0 {
			detail.ResolvedInputCount = len(materials)
		}
		for _, item := range materials {
			material, _ := item.(map[string]any)
			uri := stringAt(material, "uri")
			digestMap, _ := material["digest"].(map[string]any)
			digestStr := firstMapValue(digestMap)
			if uri != "" {
				detail.Materials = append(detail.Materials, ProvenanceMaterial{
					URI:    uri,
					Digest: digestStr,
					Kind:   classifyMaterialKind(uri),
				})
			}
			if strings.HasPrefix(uri, "git+") || strings.HasPrefix(uri, "https://github.com/") || strings.HasPrefix(uri, "https://gitlab.com/") {
				appendFact(&facts, "Source material", uri)
				setIfEmpty(&detail.SourceRepo, strings.TrimPrefix(uri, "git+"))
				if digestStr != "" {
					appendFact(&facts, "Material commit", digestStr)
					setIfEmpty(&detail.Commit, digestStr)
				}
			}
		}
	}

	detail.BuildTypeLabel = friendlyBuildType(detail.BuildType)
	detail.SourceRepoURL = safeHTTPSURL(cleanGitURI(detail.SourceRepo))
	detail.InvocationURL = safeHTTPSURL(detail.InvocationID)
	detail.CommitURL = buildCommitURL(detail.SourceRepoURL, detail.Commit)
	if !detail.StartedAt.IsZero() && !detail.FinishedAt.IsZero() && detail.FinishedAt.After(detail.StartedAt) {
		detail.Duration = formatDuration(detail.FinishedAt.Sub(detail.StartedAt))
	}

	return uniqueFacts(facts), detail
}

func slsaVersionLabel(predicateType string, predicate map[string]any) string {
	lower := strings.ToLower(predicateType)
	switch {
	case strings.Contains(lower, "provenance/v1"):
		return "SLSA v1.0"
	case strings.Contains(lower, "provenance/v0.2"):
		return "SLSA v0.2"
	case strings.Contains(lower, "provenance/v0.1"):
		return "SLSA v0.1"
	case predicate["buildDefinition"] != nil:
		return "SLSA v1.0"
	default:
		return "SLSA provenance"
	}
}

func friendlyBuildType(buildType string) string {
	lower := strings.ToLower(buildType)
	switch {
	case strings.Contains(lower, "slsa-github-generator") || strings.Contains(lower, "actions.github.io") || strings.Contains(lower, "github.com/actions"):
		return "GitHub Actions"
	case strings.Contains(lower, "mobyproject.org/buildkit") || strings.Contains(lower, "moby.buildkit"):
		return "Docker BuildKit"
	case strings.Contains(lower, "apko"):
		return "apko"
	case strings.Contains(lower, "googlecloudbuild") || strings.Contains(lower, "cloudbuild.googleapis.com"):
		return "Google Cloud Build"
	case strings.Contains(lower, "tekton"):
		return "Tekton Chains"
	case buildType == "":
		return ""
	default:
		return buildType
	}
}

func classifyMaterialKind(uri string) string {
	switch {
	case strings.HasPrefix(uri, "pkg:docker/"), strings.HasPrefix(uri, "pkg:oci/"):
		return "Container image"
	case strings.HasPrefix(uri, "git+"), strings.Contains(uri, "github.com/"), strings.Contains(uri, "gitlab.com/"):
		return "Source repository"
	default:
		return "Build material"
	}
}

func cleanGitURI(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "git+")
	if at := strings.Index(s, "@"); at > 0 && strings.HasPrefix(s, "https://") {
		s = s[:at]
	}
	s = strings.TrimSuffix(s, ".git")
	return s
}

func safeHTTPSURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return ""
	}
	return parsed.String()
}

func buildCommitURL(repoURL, commit string) string {
	if repoURL == "" || commit == "" {
		return ""
	}
	sha := commit
	if idx := strings.Index(sha, ":"); idx >= 0 {
		sha = sha[idx+1:]
	}
	sha = strings.TrimSpace(sha)
	if len(sha) < 7 || len(sha) > 64 {
		return ""
	}
	for _, r := range sha {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return ""
		}
	}
	parsed, err := url.Parse(repoURL)
	if err != nil {
		return ""
	}
	if strings.EqualFold(parsed.Host, "github.com") {
		return strings.TrimRight(repoURL, "/") + "/commit/" + sha
	}
	if strings.EqualFold(parsed.Host, "gitlab.com") {
		return strings.TrimRight(repoURL, "/") + "/-/commit/" + sha
	}
	return ""
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Second {
		return "< 1s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if m < 60 {
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm %ds", m, s)
	}
	h := m / 60
	m = m % 60
	return fmt.Sprintf("%dh %dm", h, m)
}

func extractSubjectClaims(statement map[string]any, targetDigest string) []SubjectClaim {
	subjects, _ := statement["subject"].([]any)
	var out []SubjectClaim
	for _, item := range subjects {
		sub, _ := item.(map[string]any)
		name := stringAt(sub, "name")
		digestMap, _ := sub["digest"].(map[string]any)
		digest := firstMapValue(digestMap)
		if name == "" && digest == "" {
			continue
		}
		out = append(out, SubjectClaim{
			Name:          name,
			Digest:        digest,
			MatchesTarget: targetDigest != "" && strings.EqualFold(digest, targetDigest),
		})
	}
	return out
}

func setIfEmpty(dst *string, val string) {
	if *dst == "" && strings.TrimSpace(val) != "" {
		*dst = strings.TrimSpace(val)
	}
}

func analyzeSignature(doc map[string]any) ([]oci.KV, *SignatureDetail) {
	var facts []oci.KV
	detail := &SignatureDetail{}
	if critical, ok := doc["critical"].(map[string]any); ok {
		detail.SignatureType = stringAt(critical, "type")
		detail.DockerReference = nestedString(critical, "identity", "docker-reference")
		detail.SignedDigest = nestedString(critical, "image", "docker-manifest-digest")
		appendFact(&facts, "Signature type", detail.SignatureType)
		appendFact(&facts, "Reference", detail.DockerReference)
		appendFact(&facts, "Covers", detail.SignedDigest)
	}
	if optional, ok := doc["optional"].(map[string]any); ok {
		detail.Signer = stringAt(optional, "Subject")
		detail.OIDCIssuer = stringAt(optional, "Issuer")
		appendFact(&facts, "Signer", detail.Signer)
		appendFact(&facts, "Issuer", detail.OIDCIssuer)
	}
	return facts, detail
}

func enrichSignatureFromVerification(artifact *Artifact) {
	if artifact.Verification.Certificate == nil && artifact.Verification.Rekor == nil {
		return
	}
	if artifact.Signature == nil && strings.Contains(strings.ToLower(artifact.Type), "signature") {
		artifact.Signature = &SignatureDetail{}
	}
	if artifact.Signature == nil {
		return
	}
	if cert := artifact.Verification.Certificate; cert != nil {
		setIfEmpty(&artifact.Signature.Signer, cert.PrimaryIdentity())
		setIfEmpty(&artifact.Signature.OIDCIssuer, cert.OIDCIssuer)
		setIfEmpty(&artifact.Signature.SourceRepo, cert.SourceRepoURI)
		setIfEmpty(&artifact.Signature.WorkflowRef, cert.WorkflowRef)
		setIfEmpty(&artifact.Signature.RunnerEnv, cert.RunnerEnvironment)
		setIfEmpty(&artifact.Signature.CertIssuer, cert.Issuer)
		setIfEmpty(&artifact.Signature.CertSubject, cert.Subject)
		artifact.Signature.CertValidFrom = cert.NotBefore
		artifact.Signature.CertValidUntil = cert.NotAfter
	}
	if rekor := artifact.Verification.Rekor; rekor != nil {
		setIfEmpty(&artifact.Signature.RekorLogIndex, rekor.LogIndex)
		artifact.Signature.RekorTime = rekor.IntegratedTime
		setIfEmpty(&artifact.Signature.RekorLogID, rekor.LogID)
	}
}

func appendSubjects(facts *[]oci.KV, statement map[string]any) {
	subjects, _ := statement["subject"].([]any)
	for _, subjectAny := range subjects {
		subject, _ := subjectAny.(map[string]any)
		name := stringAt(subject, "name")
		digest, _ := subject["digest"].(map[string]any)
		value := strings.TrimSpace(name + " " + firstMapValue(digest))
		appendFact(facts, "Covers", value)
	}
}

func appendFact(facts *[]oci.KV, key, value string) {
	if strings.TrimSpace(value) != "" {
		*facts = append(*facts, oci.KV{Key: key, Value: value})
	}
}

func uniqueFacts(facts []oci.KV) []oci.KV {
	seen := map[string]bool{}
	out := make([]oci.KV, 0, len(facts))
	for _, fact := range facts {
		key := fact.Key + "\x00" + fact.Value
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, fact)
	}
	return out
}

func purlDetails(purl string) (string, string) {
	if !strings.HasPrefix(purl, "pkg:") {
		return "", ""
	}
	value := strings.TrimPrefix(purl, "pkg:")
	ecosystem, rest, _ := strings.Cut(value, "/")
	parsed, _ := url.Parse("https://purl.invalid/" + rest)
	platform := parsed.Query().Get("arch")
	if osName := parsed.Query().Get("os"); osName != "" {
		platform = strings.Trim(strings.Join([]string{osName, platform}, "/"), "/")
	}
	return ecosystem, platform
}

func nestedString(doc map[string]any, path ...string) string {
	current := any(doc)
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = object[key]
	}
	value, _ := current.(string)
	return value
}

func nestedMap(doc map[string]any, path ...string) (map[string]any, bool) {
	current := any(doc)
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current = object[key]
	}
	value, ok := current.(map[string]any)
	return value, ok
}

func stringAt(doc map[string]any, key string) string {
	value, _ := doc[key].(string)
	return value
}

func stringSlice(value any) []string {
	items, _ := value.([]any)
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func firstMapValue(values map[string]any) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if value, ok := values[key].(string); ok && value != "" {
			return key + ":" + value
		}
	}
	return ""
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
