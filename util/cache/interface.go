// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package cache contains an interface for a cache around a typed value, and
// various cache implementations that implement that interface.
package cache

import "time"

// Cache is the interface for the cache types in this package.
type Cache[K comparable, V any] interface {
	// Get should return a previously-cached value or call the provided
	// FillFunc to obtain a new one. The provided key can be used either to
	// allow multiple cached values, or to drop the cache if the key
	// changes; either is valid.
	Get(K, FillFunc[V]) (V, error)

	// Forget should empty the cache such that the next call to Get should
	// call the provided FillFunc.
	Forget()
}

// FillFunc is the signature of a function for filling a cache. It should
// return the value to be cached, the time that the cached value is valid
// until, or an error
type FillFunc[T any] func() (T, time.Time, error)
