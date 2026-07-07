package oci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var ErrAuthenticationNeeded = errors.New("registry authentication is required or anonymous access was denied")

type Client struct {
	http *http.Client
}

func NewClient(timeout time.Duration) *Client {
	return &Client{http: &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			if req.URL.Scheme != "https" {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}}
}

func (c *Client) GetManifest(ctx context.Context, registry, repository, reference string) (RegistryResponse, Manifest, error) {
	accept := strings.Join([]string{
		MediaOCIIndex,
		MediaDockerManifestList,
		MediaOCIManifest,
		MediaDockerManifest,
		MediaOCIArtifactManifest,
		"application/vnd.dev.cosign.simplesigning.v1+json",
	}, ", ")
	resp, err := c.registryRequest(ctx, http.MethodGet, registry, "/v2/"+repository+"/manifests/"+reference, accept, 20<<20)
	if err != nil {
		return RegistryResponse{}, Manifest{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return RegistryResponse{}, Manifest{}, os.ErrNotExist
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return RegistryResponse{}, Manifest{}, ErrAuthenticationNeeded
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return RegistryResponse{}, Manifest{}, fmt.Errorf("registry returned HTTP %d", resp.StatusCode)
	}
	var manifest Manifest
	if err := json.Unmarshal(resp.Bytes, &manifest); err != nil {
		return RegistryResponse{}, Manifest{}, fmt.Errorf("manifest response was not valid JSON: %w", err)
	}
	if manifest.MediaType == "" {
		manifest.MediaType = resp.MediaType
	}
	return resp, manifest, nil
}

func (c *Client) GetReferrers(ctx context.Context, registry, repository, digest string, limit int) ([]Descriptor, []string) {
	resp, err := c.registryRequest(ctx, http.MethodGet, registry, "/v2/"+repository+"/referrers/"+digest, MediaOCIIndex+", "+MediaDockerManifestList, 20<<20)
	if err != nil {
		return nil, []string{"OCI referrer lookup failed: " + err.Error()}
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, []string{fmt.Sprintf("OCI referrer lookup returned HTTP %d.", resp.StatusCode)}
	}
	var rr ReferrersResponse
	if err := json.Unmarshal(resp.Bytes, &rr); err != nil {
		return nil, []string{"OCI referrer response was not valid JSON."}
	}
	if len(rr.Manifests) > limit {
		return rr.Manifests[:limit], []string{fmt.Sprintf("Referrer list truncated at %d entries.", limit)}
	}
	return rr.Manifests, nil
}

func (c *Client) GetBlob(ctx context.Context, registry, repository, digest string, maxBytes int64) ([]byte, error) {
	resp, err := c.registryRequest(ctx, http.MethodGet, registry, "/v2/"+repository+"/blobs/"+digest, "application/octet-stream, */*", maxBytes)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, os.ErrNotExist
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrAuthenticationNeeded
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("registry returned HTTP %d", resp.StatusCode)
	}
	return resp.Bytes, nil
}

func (c *Client) registryRequest(ctx context.Context, method, registry, path, accept string, maxBytes int64) (RegistryResponse, error) {
	u := url.URL{Scheme: "https", Host: RegistryAPIHost(registry), Path: path}
	resp, err := c.do(ctx, method, u.String(), accept, "", maxBytes)
	if err != nil {
		return RegistryResponse{}, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	challenge := header(resp.Headers, "WWW-Authenticate")
	token, err := c.token(ctx, challenge)
	if err != nil || token == "" {
		return resp, nil
	}
	return c.do(ctx, method, u.String(), accept, token, maxBytes)
}

func RegistryAPIHost(registry string) string {
	if registry == "docker.io" {
		return "registry-1.docker.io"
	}
	return registry
}

func (c *Client) do(ctx context.Context, method, target, accept, token string, maxBytes int64) (RegistryResponse, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return RegistryResponse{}, err
	}
	req.Header.Set("Accept", accept)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return RegistryResponse{}, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if err != nil {
		return RegistryResponse{}, err
	}
	if int64(len(body)) > maxBytes {
		return RegistryResponse{}, fmt.Errorf("registry response exceeded %d bytes", maxBytes)
	}
	mt, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if mt == "" {
		mt = res.Header.Get("Content-Type")
	}
	return RegistryResponse{
		StatusCode: res.StatusCode,
		MediaType:  mt,
		Digest:     res.Header.Get("Docker-Content-Digest"),
		Bytes:      body,
		Size:       int64(len(body)),
		Headers:    map[string][]string(res.Header.Clone()),
	}, nil
}

func (c *Client) token(ctx context.Context, challenge string) (string, error) {
	if !strings.HasPrefix(strings.ToLower(challenge), "bearer ") {
		return "", nil
	}
	params := parseAuthParams(strings.TrimSpace(challenge[len("Bearer "):]))
	realm := params["realm"]
	if realm == "" {
		return "", nil
	}
	u, err := url.Parse(realm)
	if err != nil || u.Scheme != "https" {
		return "", err
	}
	q := u.Query()
	for _, key := range []string{"service", "scope"} {
		if params[key] != "" {
			q.Set(key, params[key])
		}
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return "", fmt.Errorf("token endpoint returned HTTP %d", res.StatusCode)
	}
	var out struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if out.Token != "" {
		return out.Token, nil
	}
	return out.AccessToken, nil
}

func parseAuthParams(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		out[strings.ToLower(k)] = strings.Trim(v, `"`)
	}
	return out
}

func header(h map[string][]string, key string) string {
	for k, values := range h {
		if strings.EqualFold(k, key) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}
