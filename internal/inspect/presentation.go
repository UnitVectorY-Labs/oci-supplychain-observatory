package inspect

import (
	"fmt"
	"strings"
	"time"

	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/oci"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/verify"
)

// DefaultTargetID opens runnable evidence first; index signatures remain one click away.
func (r *Report) DefaultTargetID() string {
	best, score := -1, 0
	for i, target := range r.Platforms {
		n := target.ArtifactCount()
		if n > score {
			best, score = i, n
		}
	}
	if best >= 0 {
		return fmt.Sprintf("target-platform-%d", best)
	}
	if len(r.Platforms) > 0 {
		return "target-platform-0"
	}
	return "target-top"
}

func (r *Report) PlatformCount() int {
	if len(r.Platforms) > 0 {
		return len(r.Platforms)
	}
	if r.TopLevel.Kind != "Image index" {
		return 1
	}
	return 0
}

func (t TargetResult) ScopeLabel() string {
	if t.Kind == "Image index" {
		return "Image index"
	}
	if t.OS != "" && t.Architecture != "" {
		name := t.OS + "/" + t.Architecture
		if t.Variant != "" {
			name += "/" + t.Variant
		}
		return name
	}
	return "Image manifest"
}

func (t TargetResult) LayerBytes() int64 {
	var size int64
	for _, layer := range t.Layers {
		size += layer.Size
	}
	return size
}

func (t TargetResult) HasValidSignature() bool {
	for _, a := range t.Signatures {
		if a.Verification.State == verify.StateSignatureValid {
			return true
		}
	}
	for _, a := range t.Attestations {
		if a.Verification.State == verify.StateSignatureValid {
			return true
		}
	}
	return false
}

func (t TargetResult) PrimaryProvenance() *ProvenanceDetail {
	for _, a := range t.Attestations {
		if a.Provenance != nil {
			return a.Provenance
		}
	}
	return nil
}

func (t TargetResult) PrimarySBOM() *SBOMDetail {
	for _, a := range t.SBOMs {
		if a.SBOM != nil {
			return a.SBOM
		}
	}
	return nil
}

func (t TargetResult) PrimarySignature() *SignatureDetail {
	for _, a := range t.Signatures {
		if a.Signature != nil {
			return a.Signature
		}
	}
	for _, a := range t.Attestations {
		if a.Verification.Certificate != nil {
			return &SignatureDetail{
				Signer:         a.Verification.Certificate.PrimaryIdentity(),
				OIDCIssuer:     a.Verification.Certificate.OIDCIssuer,
				SourceRepo:     a.Verification.Certificate.SourceRepoURI,
				WorkflowRef:    a.Verification.Certificate.WorkflowRef,
				RunnerEnv:      a.Verification.Certificate.RunnerEnvironment,
				CertIssuer:     a.Verification.Certificate.Issuer,
				CertSubject:    a.Verification.Certificate.Subject,
				CertValidFrom:  a.Verification.Certificate.NotBefore,
				CertValidUntil: a.Verification.Certificate.NotAfter,
			}
		}
	}
	return nil
}

func (t TargetResult) NonSBOMArtifactCount() int {
	return len(t.Signatures) + len(t.Attestations) + len(t.OtherArtifacts)
}

func (t TargetResult) SBOMSummaryLabel() string {
	if len(t.SBOMs) == 0 {
		return "None"
	}
	if sbom := t.PrimarySBOM(); sbom != nil && !sbom.UnsupportedInventory && sbom.TotalComponentsLabel != "" {
		shortFmt := "SBOM"
		if strings.HasPrefix(strings.ToUpper(sbom.Format), "SPDX") {
			shortFmt = "SPDX"
		} else if strings.HasPrefix(strings.ToUpper(sbom.Format), "CYCLONEDX") {
			shortFmt = "CycloneDX"
		}
		return fmt.Sprintf("%s · %s pkgs", shortFmt, sbom.TotalComponentsLabel)
	}
	return t.SBOMStatus()
}

func (t TargetResult) ProvenanceSummaryLabel() string {
	if len(t.Attestations) == 0 {
		return "None"
	}
	if prov := t.PrimaryProvenance(); prov != nil && prov.SLSAVersion != "" {
		if len(t.Attestations) == 1 {
			return prov.SLSAVersion
		}
		return fmt.Sprintf("%s +%d", prov.SLSAVersion, len(t.Attestations)-1)
	}
	return t.AttestationStatus()
}

func (t TargetResult) SignatureSummaryLabel() string {
	if len(t.Signatures) == 0 {
		return "None"
	}
	validCount := 0
	for _, s := range t.Signatures {
		if s.Verification.State == verify.StateSignatureValid {
			validCount++
		}
	}
	if validCount > 0 {
		return fmt.Sprintf("%d checked", len(t.Signatures))
	}
	return t.SignatureStatus()
}

func (c *ImageConfig) UserLabel() string {
	if c == nil || strings.TrimSpace(c.User) == "" {
		return "root (default)"
	}
	return c.User
}

func (c *ImageConfig) IsNonRoot() bool {
	if c == nil {
		return false
	}
	u := strings.TrimSpace(c.User)
	if u == "" || u == "0" || u == "root" || strings.HasPrefix(u, "0:") || strings.HasPrefix(u, "root:") {
		return false
	}
	return true
}

func (c *ImageConfig) CommandSummary() string {
	if c == nil {
		return ""
	}
	parts := append(append([]string{}, c.Entrypoint...), c.Cmd...)
	return strings.Join(parts, " ")
}

func (a Artifact) DecodeStatus() string {
	if a.Error != "" {
		return "Unavailable"
	}
	if a.DecodedViewJSON {
		return "Decoded"
	}
	if a.Downloadable {
		return "Found · unsupported format"
	}
	return "Discovered"
}

// DiscoveryLabel returns a concise human-readable discovery method for badges,
// keeping full digest-derived tag names in technical details so narrow screens never overflow.
func (a Artifact) DiscoveryLabel() string {
	d := strings.TrimSpace(a.Discovery)
	switch {
	case strings.HasPrefix(d, "Cosign legacy tag "):
		switch {
		case strings.HasSuffix(d, ".sig"):
			return "Cosign .sig tag"
		case strings.HasSuffix(d, ".att"):
			return "Cosign .att tag"
		case strings.HasSuffix(d, ".sbom"):
			return "Cosign .sbom tag"
		default:
			return "Cosign legacy tag"
		}
	case strings.HasPrefix(d, "Cosign attachment index"):
		return "Cosign attachment index"
	case strings.EqualFold(d, "Image index attestation manifest"):
		return "Index attestation"
	default:
		return d
	}
}

// CertificateFacts are publisher-supplied identity details, not a trust decision.
func (a Artifact) CertificateFacts() []struct{ Key, Value string } {
	var facts []struct{ Key, Value string }
	for _, fact := range a.Summary {
		if strings.HasPrefix(fact.Key, "Certificate ") || fact.Key == "OIDC issuer" {
			facts = append(facts, struct{ Key, Value string }{fact.Key, fact.Value})
		}
	}
	return facts
}

// OverviewFacts keeps repeated subjects and protocol identifiers out of the reading path.
// The complete claims remain accessible under artifact technical details and raw payloads.
func (a Artifact) OverviewFacts() []oci.KV {
	var result []oci.KV
	for _, fact := range a.Facts {
		switch fact.Key {
		case "Covers", "Predicate", "Build type", "Build run", "Relationships", "Dependencies":
			continue
		}
		if parsed, err := time.Parse(time.RFC3339Nano, fact.Value); err == nil {
			fact.Value = parsed.UTC().Format("2006-01-02 15:04 UTC")
		}
		result = append(result, fact)
	}
	return result
}

func (r *Report) HasOtherMetadata() bool {
	if len(r.TopLevel.OtherArtifacts) > 0 {
		return true
	}
	for _, target := range r.Platforms {
		if len(target.OtherArtifacts) > 0 {
			return true
		}
	}
	return false
}

// PackagePage holds a filtered, paginated slice of SBOM components for UI rendering.
type PackagePage struct {
	ArtifactID    string
	Query         string
	Ecosystem     string
	License       string
	Items         []Component
	TotalMatched  int
	TotalAll      int
	Page          int
	PageSize      int
	TotalPages    int
	HasPrev       bool
	HasNext       bool
	PrevPage      int
	NextPage      int
	StartRow      int
	EndRow        int
	Capped        bool
}

// FilterComponents filters and paginates an SBOM artifact's components in memory.
func (a *Artifact) FilterComponents(query, ecosystem, license string, page, pageSize int) PackagePage {
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}
	if page < 1 {
		page = 1
	}
	source := a.Components
	totalAll := len(source)
	capped := a.ComponentsTruncated
	if a.SBOM != nil && len(a.SBOM.AllComponents) > 0 {
		source = a.SBOM.AllComponents
		totalAll = a.SBOM.TotalComponents
		capped = a.SBOM.ComponentsCapped
	}

	q := strings.TrimSpace(strings.ToLower(query))
	eco := strings.TrimSpace(strings.ToLower(ecosystem))
	lic := strings.TrimSpace(strings.ToLower(license))

	var matched []Component
	for _, c := range source {
		if eco != "" && strings.ToLower(c.Ecosystem) != eco {
			continue
		}
		if lic != "" && strings.ToLower(c.License) != lic {
			continue
		}
		if q != "" {
			haystack := strings.ToLower(c.Name + " " + c.Version + " " + c.Ecosystem + " " + c.License + " " + c.Supplier + " " + c.PURL)
			if !strings.Contains(haystack, q) {
				continue
			}
		}
		matched = append(matched, c)
	}

	totalMatched := len(matched)
	totalPages := (totalMatched + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	start := (page - 1) * pageSize
	end := min(start+pageSize, totalMatched)
	var items []Component
	if start < totalMatched {
		items = matched[start:end]
	}

	startRow := 0
	if totalMatched > 0 {
		startRow = start + 1
	}

	return PackagePage{
		ArtifactID:   a.ID,
		Query:        query,
		Ecosystem:    ecosystem,
		License:      license,
		Items:        items,
		TotalMatched: totalMatched,
		TotalAll:     totalAll,
		Page:         page,
		PageSize:     pageSize,
		TotalPages:   totalPages,
		HasPrev:      page > 1,
		HasNext:      page < totalPages,
		PrevPage:     page - 1,
		NextPage:     page + 1,
		StartRow:     startRow,
		EndRow:       end,
		Capped:       capped,
	}
}
