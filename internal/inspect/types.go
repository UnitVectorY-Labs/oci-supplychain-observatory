// Package inspect orchestrates OCI supply-chain metadata discovery.
package inspect

import (
	"fmt"
	"time"

	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/oci"
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
	Name          string
	Kind          string
	OS            string
	Architecture  string
	Variant       string
	Digest        string
	MediaType     string
	Size          int64
	Signatures    []Artifact
	Attestations  []Artifact
	SBOMs         []Artifact
	ReferrerCount int
	Warnings      []string
	Layers        []LayerDescriptor
	Annotations   map[string]string
	BuildInputs   []BuildInput
	Base          *BaseRelationship
}

func (t TargetResult) ArtifactCount() int {
	return len(t.Signatures) + len(t.Attestations) + len(t.SBOMs)
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

type LayerDescriptor struct {
	Digest    string
	MediaType string
	Size      int64
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
}

func (r *Report) ArtifactCount() int {
	n := r.TopLevel.ArtifactCount()
	for _, p := range r.Platforms {
		n += p.ArtifactCount()
	}
	return n
}
