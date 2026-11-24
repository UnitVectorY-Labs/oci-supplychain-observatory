// Package inspect orchestrates OCI supply-chain metadata discovery.
package inspect

import (
	"fmt"
	"time"

	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/oci"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/verify"
)

type Report struct {
	ID                  string
	Input               string
	Normalized          string
	Registry            string
	Repository          string
	Tag                 string
	ResolvedDigest      string
	Canonical           string
	InspectedAt         time.Time
	FromCache           bool
	TopLevel            TargetResult
	Platforms           []TargetResult
	Warnings            []string
	VerificationMessage string
	BuildInputs         []BuildInput
}

func (r *Report) DisplayReference() string {
	if r.Input != "" {
		return r.Input
	}
	if r.Tag != "" {
		return r.Registry + "/" + r.Repository + ":" + r.Tag
	}
	return r.Canonical
}

type TargetResult struct {
	Name               string
	Kind               string
	OS                 string
	Architecture       string
	Variant            string
	Digest             string
	MediaType          string
	Size               int64
	Signatures         []Artifact
	Attestations       []Artifact
	SBOMs              []Artifact
	OtherArtifacts     []Artifact
	ReferrerCount      int
	Warnings           []string
	Layers             []LayerDescriptor
	Annotations        map[string]string
	BuildInputs        []BuildInput
	Base               *BaseRelationship
	Config             *ImageConfig
	ManifestArtifactID string
	ConfigArtifactID   string
}

func (t TargetResult) ArtifactCount() int {
	return len(t.Signatures) + len(t.Attestations) + len(t.SBOMs) + len(t.OtherArtifacts)
}

func (t TargetResult) SignatureStatus() string {
	return evidenceStatus(len(t.Signatures))
}

func (t TargetResult) AttestationStatus() string {
	return evidenceStatus(len(t.Attestations))
}

func (t TargetResult) SBOMStatus() string {
	return evidenceStatus(len(t.SBOMs))
}

func evidenceStatus(count int) string {
	if count == 0 {
		return "Not found"
	}
	if count == 1 {
		return "1 found"
	}
	return fmt.Sprintf("%d found", count)
}

type ImageConfig struct {
	Created        time.Time
	Author         string
	User           string
	WorkingDir     string
	Entrypoint     []string
	Cmd            []string
	ExposedPorts   []string
	Volumes        []string
	StopSignal     string
	Env            []oci.KV
	Labels         []oci.KV
	OCIAnnotations []oci.KV
	History        []HistoryEntry
}

type HistoryEntry struct {
	Created    time.Time
	Command    string
	RawCommand string
	EmptyLayer bool
	Comment    string
	LayerIndex int
}

type LayerDescriptor struct {
	Index          int
	Digest         string
	MediaType      string
	ShortMediaType string
	Size           int64
	SizePercent    int
	Command        string
	RawCommand     string
	FromBase       bool
}

type BuildInput struct {
	Reference       string
	Canonical       string
	Digest          string
	Registry        string
	Repository      string
	Tag             string
	Role            string
	Platforms       []string
	Evidence        []string
	Inspectable     bool
	SharedLayers    int
	BaseLayerCount  int
	AddedLayerCount int
}

type BaseRelationship struct {
	BuildInput
}

type Component struct {
	Name      string
	Version   string
	Ecosystem string
	Supplier  string
	License   string
	Platform  string
	PURL      string
}

type FacetCount struct {
	Name  string
	Count int
}

type SubjectClaim struct {
	Name          string
	Digest        string
	MatchesTarget bool
}

type ProvenanceMaterial struct {
	URI    string
	Digest string
	Kind   string
}

type ProvenanceDetail struct {
	SLSAVersion        string
	BuildType          string
	BuildTypeLabel     string
	Builder            string
	SourceRepo         string
	SourceRepoURL      string
	SourceRef          string
	Commit             string
	CommitURL          string
	Workflow           string
	Dockerfile         string
	InvocationID       string
	InvocationURL      string
	StartedAt          time.Time
	FinishedAt         time.Time
	Duration           string
	ResolvedInputCount int
	Subjects           []SubjectClaim
	Materials          []ProvenanceMaterial
}

type SBOMDetail struct {
	Format               string
	DocumentName         string
	Created              time.Time
	Creators             []string
	TotalComponents      int
	TotalComponentsLabel string
	ComponentsCapped     bool
	RelationshipCount    int
	RelationshipLabel    string
	UnsupportedInventory bool
	Ecosystems           []FacetCount
	Licenses             []FacetCount
	AllComponents        []Component
}

type SignatureDetail struct {
	SignatureType   string
	DockerReference string
	SignedDigest    string
	Signer          string
	OIDCIssuer      string
	SourceRepo      string
	WorkflowRef     string
	RunnerEnv       string
	CertIssuer      string
	CertSubject     string
	CertValidFrom   time.Time
	CertValidUntil  time.Time
	RekorLogIndex   string
	RekorTime       time.Time
	RekorLogID      string
}

type Artifact struct {
	ID                   string
	TargetDigest         string
	Type                 string
	Discovery            string
	Digest               string
	MediaType            string
	ArtifactType         string
	Size                 int64
	VerificationStatus   string
	Verification         verify.Result
	Summary              []oci.KV
	Signatures           []oci.KV
	Preview              string
	PreviewTruncated     bool
	RawView              string
	RawViewTruncated     bool
	DecodedView          string
	DecodedViewChanged   bool
	DecodedViewJSON      bool
	DecodedViewTruncated bool
	DecodedRows          []oci.PayloadRow
	DecodedRowsTruncated bool
	Downloadable         bool
	Raw                  []byte
	Error                string
	Purpose              string
	Facts                []oci.KV
	Components           []Component
	ComponentsTruncated  bool
	Provenance           *ProvenanceDetail
	SBOM                 *SBOMDetail
	Signature            *SignatureDetail
	ClaimedDigests       []string
}

func (r *Report) ArtifactCount() int {
	n := r.TopLevel.ArtifactCount()
	for _, p := range r.Platforms {
		n += p.ArtifactCount()
	}
	return n
}

func (r *Report) SignatureCount() int {
	n := len(r.TopLevel.Signatures)
	for _, p := range r.Platforms {
		n += len(p.Signatures)
	}
	return n
}

func (r *Report) AttestationCount() int {
	n := len(r.TopLevel.Attestations)
	for _, p := range r.Platforms {
		n += len(p.Attestations)
	}
	return n
}

func (r *Report) SBOMCount() int {
	n := len(r.TopLevel.SBOMs)
	for _, p := range r.Platforms {
		n += len(p.SBOMs)
	}
	return n
}
