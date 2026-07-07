// Package config contains runtime configuration for the observatory.
package config

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

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

func Load() Config {
	allowed := env("OSO_ALLOWED_REGISTRIES", env("CTI_ALLOWED_REGISTRIES", "ghcr.io,registry.k8s.io,gcr.io,quay.io,docker.io"))
	list := splitCSV(allowed)
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
	}
}

func env(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, strings.ToLower(p))
		}
	}
	sort.Strings(out)
	return out
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
