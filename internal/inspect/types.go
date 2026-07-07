// Package inspect orchestrates OCI supply-chain metadata discovery.
package inspect

import (
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
}

func (t TargetResult) ArtifactCount() int {
	return len(t.Signatures) + len(t.Attestations) + len(t.SBOMs)
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
}

func (r *Report) ArtifactCount() int {
	n := r.TopLevel.ArtifactCount()
	for _, p := range r.Platforms {
		n += p.ArtifactCount()
	}
	return n
}
