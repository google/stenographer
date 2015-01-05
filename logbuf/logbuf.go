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

// Package logbuf provides an in-memory log as an io.Writer which also acts as
// an http.Handler for serving the log back to users.
package logbuf

import (
	"bytes"
	"fmt"
	"net/http"
	"sync"
)

// LogBuf acts as a log sync (it's an io.Writer) which can serve its current
// contents via HTTP.
type LogBuf struct {
	size int
	mu   sync.Mutex
	buf  bytes.Buffer
}

// New returns a new LogBuf that acts as a circular buffer of 'size' bytes.
func New(size int) *LogBuf {
	return &LogBuf{size: size}
}

// Write implements io.Writer.
func (l *LogBuf) Write(data []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, err := l.buf.Write(data)
	for l.buf.Len() > l.size {
		// Pop a line at a time, so we keep full log lines.
		l.buf.ReadString('\n')
	}
	return n, err
}

// ServeHTTP implements http.Handler.
func (l *LogBuf) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	out := make([]byte, l.buf.Len())
	copy(out, l.buf.Bytes())
	l.mu.Unlock()
	fmt.Fprintf(w, "<pre>")
	w.Write(out)
	fmt.Fprintf(w, "</pre>")
}
