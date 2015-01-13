// Copyright 2014 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package stats provides a simple method for exporting statistics to HTTP.
package stats

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

// Stat provides a method of exporting a single named variable.
type Stat struct {
	int64 // embedded to remain hidden
}

// Stats provides a mapping of named variables.
type Stats struct {
	mu   sync.RWMutex
	vars map[string]*Stat
}

// Get returns the stat with the given name, creating it if necessary.
func (s *Stats) Get(name string) *Stat {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vars[name] == nil {
		s.vars[name] = &Stat{}
	}
	return s.vars[name]
}

// Set sets the value of this stat to the given val.
func (s *Stat) Set(val int64) {
	atomic.StoreInt64(&s.int64, val)
}
func (s *Stat) get() int64 {
	return atomic.LoadInt64(&s.int64)
}

// IncrementBy increments this stat by the given delta.
func (s *Stat) IncrementBy(delta int64) {
	atomic.AddInt64(&s.int64, delta)
}

// Increment increments this stat by 1.
func (s *Stat) Increment() {
	s.IncrementBy(1)
}

// ServeHTTP makes Stats an http.Handler.
func (s *Stats) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	s.mu.RLock()
	defer s.mu.RUnlock()
	strs := make([]string, 0, len(s.vars))
	for k := range s.vars {
		strs = append(strs, k)
	}
	sort.Strings(strs)
	for _, k := range strs {
		fmt.Fprintf(w, "%v\t%v\n", k, s.vars[k].get())
	}
}

// S is a Stats singleton.
var S = &Stats{vars: map[string]*Stat{}}
