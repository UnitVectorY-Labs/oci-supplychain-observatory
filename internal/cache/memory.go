// Package cache defines the inspection cache boundary.
package cache

import (
	"context"
	"sync"
	"time"
)

type Entry[T any] struct {
	Value     T
	StoredAt  time.Time
	ExpiresAt time.Time
}

type Cache[T any] interface {
	Get(ctx context.Context, key string) (Entry[T], bool)
	Set(ctx context.Context, key string, value T, ttl time.Duration)
}

type Memory[T any] struct {
	mu    sync.Mutex
	items map[string]Entry[T]
	now   func() time.Time
}

func NewMemory[T any]() *Memory[T] {
	return &Memory[T]{items: map[string]Entry[T]{}, now: time.Now}
}

func (m *Memory[T]) Get(_ context.Context, key string) (Entry[T], bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.items[key]
	if !ok {
		var zero Entry[T]
		return zero, false
	}
	if !entry.ExpiresAt.IsZero() && m.now().After(entry.ExpiresAt) {
		delete(m.items, key)
		var zero Entry[T]
		return zero, false
	}
	return entry, true
}

func (m *Memory[T]) Set(_ context.Context, key string, value T, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := Entry[T]{Value: value, StoredAt: m.now()}
	if ttl > 0 {
		entry.ExpiresAt = entry.StoredAt.Add(ttl)
	}
	m.items[key] = entry
}
