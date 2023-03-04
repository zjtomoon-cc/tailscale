// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cache

import "time"

// Memory is a simple in-memory cache that stores a value until a defined time
// before it is re-fetched. It also supports returning a previously-expired
// value if refreshing the value in the cache fails.
type Memory[K comparable, V any] struct {
	key       K
	val       V
	goodUntil time.Time
	timeNow   func() time.Time // for tests

	// ServeExpired indicates that if an error occurs when filling the
	// cache, an expired value can be returned instead of an error.
	ServeExpired bool
}

// Get will return the cached value, if any, or fill the cache by calling f and
// return the corresponding value. If f returns an error and c.ServeExpired is
// true, then a previous expired value can be returned with no error.
func (c *Memory[K, V]) Get(key K, f FillFunc[V]) (V, error) {
	var now time.Time
	if c.timeNow != nil {
		now = c.timeNow()
	} else {
		now = time.Now()
	}

	if c.key == key && now.Before(c.goodUntil) {
		return c.val, nil
	}

	// Re-fill cached entry
	val, until, err := f()
	if err == nil {
		c.key = key
		c.val = val
		c.goodUntil = until
		return val, nil
	}

	// Never serve an expired entry for the wrong key.
	if c.key == key && c.ServeExpired && !c.goodUntil.IsZero() {
		return c.val, nil
	}

	var zero V
	return zero, err
}

// Forget implements Cache.
func (c *Memory[K, V]) Forget() {
	c.goodUntil = time.Time{}

	var zeroKey K
	c.key = zeroKey

	var zeroVal V
	c.val = zeroVal
}
