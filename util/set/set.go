// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package set contains set types.
package set

// Set is a set of T.
type Set[T comparable] map[T]struct{}

// New returns a new Set.
func New[T comparable]() Set[T] {
	return make(Set[T])
}

// NewFromSlice returns a new set constructed from the elements in slice.
func NewFromSlice[T comparable](slice []T) Set[T] {
	s := New[T]()
	s.AddSlice(slice)
	return s
}

// Add adds e to the set.
func (s Set[T]) Add(e T) { s[e] = struct{}{} }

// AddSlice adds each element of es to the set.
func (s Set[T]) AddSlice(es []T) {
	for _, e := range es {
		s.Add(e)
	}
}

// Slice returns the elements of the set as a slice. The elements will not be
// in any particular order.
func (s Set[T]) Slice() []T {
	es := make([]T, 0, s.Len())
	for k := range s {
		es = append(es, k)
	}
	return es
}

// Delete removes e from the set.
func (s Set[T]) Delete(e T) { delete(s, e) }

// Contains reports whether s contains e.
func (s Set[T]) Contains(e T) bool {
	_, ok := s[e]
	return ok
}

// Len reports the number of items in s.
func (s Set[T]) Len() int { return len(s) }
