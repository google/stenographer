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

// Package httplog wraps a http.ResponseWriter to allow request logging.
package httplog

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

type httpLog struct {
	r      *http.Request
	w      http.ResponseWriter
	nBytes int
	code   int
	err    error
	start  time.Time
	body   string
}

func New(w http.ResponseWriter, r *http.Request, logRequestBody bool) http.ResponseWriter {
	h := &httpLog{w: w, r: r, start: time.Now(), code: http.StatusOK}
	if logRequestBody {
		var buf bytes.Buffer
		_, h.err = io.Copy(&buf, r.Body)
		r.Body.Close()
		r.Body = ioutil.NopCloser(&buf)
		h.body = fmt.Sprintf(" RequestBody:%q", buf.String())
	}
	return h
}

func (h *httpLog) Header() http.Header {
	return h.w.Header()
}

func (h *httpLog) Write(data []byte) (int, error) {
	n, err := h.w.Write(data)
	h.nBytes += n
	if err != nil && h.err == nil {
		h.err = err
	}
	return n, err
}

func (h *httpLog) WriteHeader(code int) {
	h.code = code
	h.w.WriteHeader(code)
}

func (h *httpLog) String() string {
	return fmt.Sprintf("Requester:%q Request:\"%v %v %v\" Time:%v Bytes:%v Code:%v Err:%v%v",
		h.r.RemoteAddr,
		h.r.Method,
		h.r.URL,
		h.r.Proto,
		time.Since(h.start),
		h.nBytes,
		http.StatusText(h.code),
		h.err,
		h.body)
}
