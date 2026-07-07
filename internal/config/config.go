// Package config contains runtime configuration for the observatory.
package config

import (
	_ "embed"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed registries.yaml
var registriesYAML []byte

const (
	DefaultMaxArtifactBytes = 10 << 20
	DefaultMaxPreviewBytes  = 512 << 10
	DefaultMaxPlatforms     = 50
	DefaultMaxReferrers     = 100
)

type Config struct {
	HTTPAddr         string
	AllowedRegistry  map[string]bool
	AllowedList      []string
	RequestTimeout   time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	IdleTimeout      time.Duration
	MaxArtifactBytes int64
	MaxPreviewBytes  int64
	MaxPlatforms     int
	MaxReferrers     int
}

type registryConfig struct {
	Registries []string `yaml:"registries"`
}

func LoadRegistries() ([]string, error) {
	var cfg registryConfig
	if err := yaml.Unmarshal(registriesYAML, &cfg); err != nil {
		return nil, err
	}
	return normalizeHosts(cfg.Registries), nil
}

func Load() (Config, error) {
	var list []string
	var err error

	if os.Getenv("OSO_ALLOWED_REGISTRIES") != "" || os.Getenv("CTI_ALLOWED_REGISTRIES") != "" {
		allowed := env("OSO_ALLOWED_REGISTRIES", env("CTI_ALLOWED_REGISTRIES", ""))
		list = splitCSV(allowed)
	} else {
		list, err = LoadRegistries()
		if err != nil {
			return Config{}, err
		}
	}

	allowedMap := make(map[string]bool, len(list))
	for _, host := range list {
		allowedMap[strings.ToLower(host)] = true
	}
	return Config{
		HTTPAddr:         env("OSO_HTTP_ADDR", env("CTI_HTTP_ADDR", ":8080")),
		AllowedRegistry:  allowedMap,
		AllowedList:      list,
		RequestTimeout:   durationEnv("OSO_REQUEST_TIMEOUT", 20*time.Second),
		ReadTimeout:      durationEnv("OSO_READ_TIMEOUT", 10*time.Second),
		WriteTimeout:     durationEnv("OSO_WRITE_TIMEOUT", 45*time.Second),
		IdleTimeout:      durationEnv("OSO_IDLE_TIMEOUT", 120*time.Second),
		MaxArtifactBytes: int64Env("OSO_MAX_ARTIFACT_BYTES", DefaultMaxArtifactBytes),
		MaxPreviewBytes:  int64Env("OSO_MAX_PREVIEW_BYTES", DefaultMaxPreviewBytes),
		MaxPlatforms:     intEnv("OSO_MAX_PLATFORMS", DefaultMaxPlatforms),
		MaxReferrers:     intEnv("OSO_MAX_REFERRERS", DefaultMaxReferrers),
	}, nil
}

func env(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}

func normalizeHosts(hosts []string) []string {
	var out []string
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, strings.ToLower(h))
		}
	}
	sort.Strings(out)
	return out
}

func splitCSV(s string) []string {
	return normalizeHosts(strings.Split(s, ","))
}

func durationEnv(k string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func int64Env(k string, fallback int64) int64 {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func intEnv(k string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}
