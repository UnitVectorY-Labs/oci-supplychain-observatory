[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT) [![Work In Progress](https://img.shields.io/badge/Status-Work%20In%20Progress-yellow)](https://guide.unitvectorylabs.com/bestpractices/status/#work-in-progress) 

# oci-supplychain-observatory

Inspect public OCI image supply chain metadata, including signatures, attestations, and SBOMs.

The interface resolves tags to immutable digests, discovers OCI referrers and legacy Cosign attachments, summarizes common supply-chain formats, and explains decoded fields while preserving the raw payload for comparison. Published provenance may expose digest-pinned container build inputs for follow-on inspection. The application does not pull image layers, generate SBOMs, or infer a base image from layer overlap.

Artifact discovery and decoding are not signature verification. The current UI labels artifacts as not verified until cryptographic verification and a trust policy are implemented.
