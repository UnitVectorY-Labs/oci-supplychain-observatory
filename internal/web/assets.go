package web

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"strings"
)

const assetVersionLength = 12

var versionedAssetPaths = []string{
	"/static/css/style.css",
	"/static/js/script.js",
	"/static/js/htmx.min.js",
}

func buildAssetVersions(staticFiles fs.FS, assetPaths []string) (map[string]string, error) {
	versions := make(map[string]string, len(assetPaths))
	for _, path := range assetPaths {
		assetBytes, err := fs.ReadFile(staticFiles, strings.TrimPrefix(path, "/"))
		if err != nil {
			return nil, fmt.Errorf("read asset %q: %w", path, err)
		}
		sum := sha256.Sum256(assetBytes)
		versions[path] = hex.EncodeToString(sum[:])[:assetVersionLength]
	}
	return versions, nil
}

func assetURL(path string, versions map[string]string) string {
	version, ok := versions[path]
	if !ok {
		return path
	}
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return path + separator + "v=" + version
}
