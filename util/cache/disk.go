// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cache

import (
	"encoding/json"
	"os"
	"time"
)

// Disk is a cache that stores data in a file on-disk. It also supports
// returning a previously-expired value if refreshing the value in the cache
// fails.
type Disk[K comparable, V any] struct {
	key       K
	val       V
	goodUntil time.Time
	path      string
	timeNow   func() time.Time // for tests

	// ServeExpired indicates that if an error occurs when filling the
	// cache, an expired value can be returned instead of an error.
	ServeExpired bool
}

type diskValue[K comparable, V any] struct {
	Key   K
	Value V
	Until time.Time // Always UTC
}

func NewDisk[K comparable, V any](path string) (*Disk[K, V], error) {
	f, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		// Ignore "does not exist" errors
		return &Disk[K, V]{path: path}, nil
	}
	defer f.Close()

	var dv diskValue[K, V]
	if err := json.NewDecoder(f).Decode(&dv); err != nil {
		// Ignore errors; we'll overwrite when filling.
		return &Disk[K, V]{path: path}, nil
	}

	return &Disk[K, V]{
		key:       dv.Key,
		val:       dv.Value,
		goodUntil: dv.Until,
		path:      path,
	}, nil
}

// Get will return the cached value, if any, or fill the cache by calling f and
// return the corresponding value. When the cache is filled, the value will be
// written to the configured path on-disk, along with the expiry time. Writing
// to the path on-disk is non-fatal.
//
// If f returns an error and c.ServeExpired is true, then a previous expired
// value can be returned with no error.
func (d *Disk[K, V]) Get(key K, f FillFunc[V]) (V, error) {
	var now time.Time
	if d.timeNow != nil {
		now = d.timeNow()
	} else {
		now = time.Now()
	}

	if d.key == key && now.Before(d.goodUntil) {
		return d.val, nil
	}

	// Re-fill cached entry
	val, until, err := f()
	if err == nil {
		d.key = key
		d.val = val
		d.goodUntil = until
		d.write()
		return val, nil
	}

	// Never serve an expired entry for the wrong key.
	if d.key == key && d.ServeExpired && !d.goodUntil.IsZero() {
		return d.val, nil
	}

	var zero V
	return zero, err
}

func (d *Disk[K, V]) write() {
	// Try writing to the file on-disk, but ignore errors.
	b, err := json.Marshal(diskValue[K, V]{
		Key:   d.key,
		Value: d.val,
		Until: d.goodUntil.UTC(),
	})
	if err == nil {
		os.WriteFile(d.path, b, 0600)
	}
}

// Forget implements Cache.
func (c *Disk[K, V]) Forget(key K) {
	if c.key != key {
		return
	}

	c.Empty()
}

// Empty implements Cache.
func (d *Disk[K, V]) Empty() {
	d.goodUntil = time.Time{}

	var zeroKey K
	d.key = zeroKey

	var zeroVal V
	d.val = zeroVal

	d.write()
}
