// Package reference validates and normalizes OCI image references.
package reference

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

const MaxInputLen = 512

var (
	ErrInvalidInput       = errors.New("invalid image reference")
	ErrRegistryNotAllowed = errors.New("registry is not allow-listed")
	digestRE              = regexp.MustCompile(`^sha256:[a-fA-F0-9]{64}$`)
)

type Config struct {
	AllowedRegistry map[string]bool
}

type ImageRef struct {
	Original   string
	Registry   string
	Repository string
	Tag        string
	Digest     string
	Normalized string
}

func Parse(input string, cfg Config) (ImageRef, error) {
	original := strings.TrimSpace(input)
	if original == "" || len(original) > MaxInputLen || strings.ContainsAny(original, " \t\r\n") {
		return ImageRef{}, fmt.Errorf("%w: enter one container image reference", ErrInvalidInput)
	}
	if strings.Contains(original, "://") || strings.HasPrefix(original, "/") || strings.HasPrefix(original, ".") {
		return ImageRef{}, fmt.Errorf("%w: URLs and file paths are not accepted", ErrInvalidInput)
	}
	if strings.Count(original, "@") > 1 {
		return ImageRef{}, fmt.Errorf("%w: malformed digest reference", ErrInvalidInput)
	}

	namePart, digest := original, ""
	if left, right, ok := strings.Cut(original, "@"); ok {
		namePart, digest = left, strings.ToLower(right)
		if !digestRE.MatchString(digest) {
			return ImageRef{}, fmt.Errorf("%w: only sha256 digest references are supported", ErrInvalidInput)
		}
	}

	tag := ""
	lastSlash := strings.LastIndex(namePart, "/")
	lastColon := strings.LastIndex(namePart, ":")
	if lastColon > lastSlash {
		tag = namePart[lastColon+1:]
		namePart = namePart[:lastColon]
		if tag == "" {
			return ImageRef{}, fmt.Errorf("%w: empty tag", ErrInvalidInput)
		}
	}
	if digest == "" && tag == "" {
		tag = "latest"
	}

	parts := strings.Split(namePart, "/")
	registry := ""
	repoParts := parts
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost") {
		registry = strings.ToLower(parts[0])
		repoParts = parts[1:]
	} else {
		registry = "docker.io"
		if len(repoParts) == 1 {
			repoParts = append([]string{"library"}, repoParts...)
		}
	}
	repository := strings.Join(repoParts, "/")
	if err := validateRegistry(registry, cfg); err != nil {
		return ImageRef{}, err
	}
	if err := validateRepository(repository); err != nil {
		return ImageRef{}, err
	}
	if tag != "" && !validTag(tag) {
		return ImageRef{}, fmt.Errorf("%w: invalid tag", ErrInvalidInput)
	}

	normalized := registry + "/" + repository
	if digest != "" {
		normalized += "@" + digest
	} else {
		normalized += ":" + tag
	}
	return ImageRef{Original: original, Registry: registry, Repository: repository, Tag: tag, Digest: digest, Normalized: normalized}, nil
}

func validateRegistry(registry string, cfg Config) error {
	if registry == "localhost" || strings.HasPrefix(registry, "localhost:") {
		return fmt.Errorf("%w: localhost registries are not permitted", ErrInvalidInput)
	}
	host := registry
	if h, _, err := net.SplitHostPort(registry); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("%w: private or local registry addresses are not permitted", ErrInvalidInput)
		}
		return fmt.Errorf("%w: IP literal registries are not permitted", ErrInvalidInput)
	}
	if !cfg.AllowedRegistry[strings.ToLower(registry)] {
		return fmt.Errorf("%w: %s is not in the server allow-list", ErrRegistryNotAllowed, registry)
	}
	return nil
}

func validateRepository(repository string) error {
	if repository == "" || strings.Contains(repository, "..") || strings.Contains(repository, "//") {
		return fmt.Errorf("%w: invalid repository", ErrInvalidInput)
	}
	for _, p := range strings.Split(repository, "/") {
		if p == "" {
			return fmt.Errorf("%w: invalid repository", ErrInvalidInput)
		}
		for _, r := range p {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
				return fmt.Errorf("%w: repository names must be lowercase and registry-safe", ErrInvalidInput)
			}
		}
	}
	return nil
}

func validTag(tag string) bool {
	if len(tag) > 128 {
		return false
	}
	for i, r := range tag {
		if i == 0 && (r == '.' || r == '-') {
			return false
		}
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

func (r ImageRef) Reference() string {
	if r.Digest != "" {
		return r.Digest
	}
	return r.Tag
}
