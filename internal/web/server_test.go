package web

import (
	"testing"

	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/cache"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/config"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/inspect"
)

func TestNewParsesTemplates(t *testing.T) {
	cfg := config.Config{
		AllowedList:     []string{"ghcr.io"},
		AllowedRegistry: map[string]bool{"ghcr.io": true},
	}
	service := inspect.NewService(cfg, nil, cache.NewMemory[*inspect.Report](), nil)
	if _, err := New(cfg, service, nil); err != nil {
		t.Fatal(err)
	}
}
