package oci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var ErrAuthenticationNeeded = errors.New("registry authentication is required or anonymous access was denied")

const (
	maxCachedTokens    = 256
	defaultTokenTTL    = 5 * time.Minute
	tokenExpiryBuffer  = 30 * time.Second
	maxReferrerPages   = 5
	maxManifestBytes   = 20 << 20
	maxTokenBodyBytes  = 1 << 20
)

type cachedToken struct {
	value     string
	expiresAt time.Time
}

type Client struct {
	http      *http.Client
	tokenMu   sync.Mutex
	tokens    map[string]cachedToken
}

func NewClient(timeout time.Duration) *Client {
	return &Client{
		http: &http.Client{
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
		},
		tokens: map[string]cachedToken{},
	}
}

func (c *Client) GetManifest(ctx context.Context, registry, repository, reference string) (RegistryResponse, Manifest, error) {
	accept := strings.Join([]string{
		MediaOCIIndex,
		MediaDockerManifestList,
		MediaOCIManifest,
		MediaDockerManifest,
		MediaOCIArtifactManifest,
		MediaCosignSimpleSigning,
	}, ", ")
	resp, err := c.registryRequest(ctx, http.MethodGet, registry, repository, "/v2/"+repository+"/manifests/"+reference, accept, maxManifestBytes)
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
	if strings.HasPrefix(strings.ToLower(reference), "sha256:") {
		if !strings.EqualFold(DigestOf(resp.Bytes), reference) {
			return RegistryResponse{}, Manifest{}, fmt.Errorf("manifest digest mismatch for %s", reference)
		}
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
	nextPath := "/v2/" + repository + "/referrers/" + digest
	accept := MediaOCIIndex + ", " + MediaDockerManifestList
	var all []Descriptor
	var warnings []string

	for page := 0; page < maxReferrerPages && nextPath != ""; page++ {
		resp, err := c.registryRequest(ctx, http.MethodGet, registry, repository, nextPath, accept, maxManifestBytes)
		if err != nil {
			slog.Warn("OCI referrer lookup failed", "registry", registry, "repository", repository, "error", err)
			if len(all) == 0 {
				return nil, []string{"OCI referrer lookup could not be completed. Evidence may be incomplete."}
			}
			warnings = append(warnings, "Additional OCI referrer pages could not be loaded.")
			break
		}
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			break
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			warnings = append(warnings, fmt.Sprintf("OCI referrer lookup returned HTTP %d.", resp.StatusCode))
			break
		}
		var rr ReferrersResponse
		if err := json.Unmarshal(resp.Bytes, &rr); err != nil {
			warnings = append(warnings, "OCI referrer response was not valid JSON.")
			break
		}
		all = append(all, rr.Manifests...)
		if limit > 0 && len(all) > limit {
			all = all[:limit]
			warnings = append(warnings, fmt.Sprintf("Referrer list truncated at %d entries.", limit))
			break
		}
		nextPath = parseNextReferrerPath(header(resp.Headers, "Link"), RegistryAPIHost(registry))
		if nextPath != "" && page+1 >= maxReferrerPages {
			warnings = append(warnings, "Referrer list truncated after maximum pagination depth.")
		}
	}
	return all, warnings
}

func parseNextReferrerPath(linkHeader, expectedHost string) string {
	if linkHeader == "" {
		return ""
	}
	for _, part := range strings.Split(linkHeader, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(strings.ToLower(part), `rel="next"`) && !strings.Contains(strings.ToLower(part), "rel=next") {
			continue
		}
		start := strings.Index(part, "<")
		end := strings.Index(part, ">")
		if start < 0 || end <= start+1 {
			continue
		}
		rawURL := strings.TrimSpace(part[start+1 : end])
		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		// Only follow relative paths or URLs on the exact same HTTPS registry host.
		if parsed.IsAbs() {
			if parsed.Scheme != "https" || !strings.EqualFold(parsed.Host, expectedHost) {
				continue
			}
		}
		if !strings.HasPrefix(parsed.Path, "/v2/") {
			continue
		}
		if parsed.RawQuery != "" {
			return parsed.Path + "?" + parsed.RawQuery
		}
		return parsed.Path
	}
	return ""
}

func (c *Client) GetBlob(ctx context.Context, registry, repository, digest string, maxBytes int64) ([]byte, error) {
	resp, err := c.registryRequest(ctx, http.MethodGet, registry, repository, "/v2/"+repository+"/blobs/"+digest, "application/octet-stream, */*", maxBytes)
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
	if strings.HasPrefix(strings.ToLower(digest), "sha256:") {
		if !strings.EqualFold(DigestOf(resp.Bytes), digest) {
			return nil, fmt.Errorf("blob digest mismatch for %s", digest)
		}
	}
	return resp.Bytes, nil
}

func (c *Client) registryRequest(ctx context.Context, method, registry, repository, pathAndQuery, accept string, maxBytes int64) (RegistryResponse, error) {
	targetURL := buildRegistryURL(registry, pathAndQuery)
	cacheKey := registry + "\x00" + repository

	if tok := c.getCachedToken(cacheKey); tok != "" {
		resp, err := c.do(ctx, method, targetURL, accept, tok, maxBytes)
		if err != nil {
			return RegistryResponse{}, err
		}
		if resp.StatusCode != http.StatusUnauthorized {
			return resp, nil
		}
		c.deleteCachedToken(cacheKey)
		challenge := header(resp.Headers, "WWW-Authenticate")
		freshTok, ttl, tokErr := c.token(ctx, challenge)
		if tokErr != nil || freshTok == "" {
			return resp, nil
		}
		c.setCachedToken(cacheKey, freshTok, ttl)
		return c.do(ctx, method, targetURL, accept, freshTok, maxBytes)
	}

	resp, err := c.do(ctx, method, targetURL, accept, "", maxBytes)
	if err != nil {
		return RegistryResponse{}, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	challenge := header(resp.Headers, "WWW-Authenticate")
	tok, ttl, err := c.token(ctx, challenge)
	if err != nil || tok == "" {
		return resp, nil
	}
	c.setCachedToken(cacheKey, tok, ttl)
	return c.do(ctx, method, targetURL, accept, tok, maxBytes)
}

func buildRegistryURL(registry, pathAndQuery string) string {
	path, rawQuery, _ := strings.Cut(pathAndQuery, "?")
	u := url.URL{Scheme: "https", Host: RegistryAPIHost(registry), Path: path, RawQuery: rawQuery}
	return u.String()
}

func (c *Client) getCachedToken(key string) string {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	entry, ok := c.tokens[key]
	if !ok {
		return ""
	}
	if time.Now().After(entry.expiresAt) {
		delete(c.tokens, key)
		return ""
	}
	return entry.value
}

func (c *Client) setCachedToken(key, value string, ttl time.Duration) {
	if value == "" || ttl <= 0 {
		return
	}
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	now := time.Now()
	if len(c.tokens) >= maxCachedTokens {
		for k, v := range c.tokens {
			if now.After(v.expiresAt) {
				delete(c.tokens, k)
			}
		}
		if len(c.tokens) >= maxCachedTokens {
			for k := range c.tokens {
				delete(c.tokens, k)
				break
			}
		}
	}
	c.tokens[key] = cachedToken{value: value, expiresAt: now.Add(ttl)}
}

func (c *Client) deleteCachedToken(key string) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	delete(c.tokens, key)
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

func (c *Client) token(ctx context.Context, challenge string) (string, time.Duration, error) {
	if !strings.HasPrefix(strings.ToLower(challenge), "bearer ") {
		return "", 0, nil
	}
	params := parseAuthParams(strings.TrimSpace(challenge[len("Bearer "):]))
	realm := params["realm"]
	if realm == "" {
		return "", 0, nil
	}
	u, err := url.Parse(realm)
	if err != nil || u.Scheme != "https" {
		return "", 0, err
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
		return "", 0, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxTokenBodyBytes))
	if err != nil {
		return "", 0, err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return "", 0, fmt.Errorf("token endpoint returned HTTP %d", res.StatusCode)
	}
	var out struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", 0, err
	}
	ttl := defaultTokenTTL
	if out.ExpiresIn > 0 {
		candidate := time.Duration(out.ExpiresIn)*time.Second - tokenExpiryBuffer
		if candidate > 10*time.Second {
			ttl = candidate
		} else {
			ttl = 10 * time.Second
		}
	}
	if out.Token != "" {
		return out.Token, ttl, nil
	}
	return out.AccessToken, ttl, nil
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
