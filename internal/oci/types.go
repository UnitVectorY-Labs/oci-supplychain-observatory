// Package oci contains registry protocol types and OCI metadata helpers.
package oci

const (
	MediaDockerManifest      = "application/vnd.docker.distribution.manifest.v2+json"
	MediaDockerManifestList  = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaOCIManifest         = "application/vnd.oci.image.manifest.v1+json"
	MediaOCIIndex            = "application/vnd.oci.image.index.v1+json"
	MediaOCIArtifactManifest = "application/vnd.oci.artifact.manifest.v1+json"
	MediaCosignSimpleSigning = "application/vnd.dev.cosign.simplesigning.v1+json"
	MediaDSSEEnvelope        = "application/vnd.dsse.envelope.v1+json"
)

type Descriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	ArtifactType string            `json:"artifactType"`
	Annotations  map[string]string `json:"annotations"`
	Platform     *Platform         `json:"platform"`
}

type Platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant"`
}

type Manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Manifests     []Descriptor      `json:"manifests"`
	Subject       *Descriptor       `json:"subject"`
	ArtifactType  string            `json:"artifactType"`
	Annotations   map[string]string `json:"annotations"`
}

type ReferrersResponse struct {
	Manifests []Descriptor `json:"manifests"`
}

type RegistryResponse struct {
	StatusCode int
	MediaType  string
	Digest     string
	Bytes      []byte
	Size       int64
	Headers    map[string][]string
}

func KindForMediaType(mt string) string {
	if mt == MediaOCIIndex || mt == MediaDockerManifestList {
		return "Image index"
	}
	if mt == MediaOCIArtifactManifest {
		return "Artifact manifest"
	}
	return "Image manifest"
}

func PlatformName(p *Platform) string {
	name := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		name += "/" + p.Variant
	}
	return name
}
