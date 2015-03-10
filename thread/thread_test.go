// Copyright 2015 Google Inc. All rights reserved.
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

package thread

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/stenographer/config"
)

func createThreads(t *testing.T) []*Thread {
	var tc = []config.ThreadConfig{
		{"/tmp/threadtest/pkt/", "/tmp/threadtest/idx/", 10, 10},
	}
	threads, err := Threads(tc, "/tmp/threadtest/")
	if err != nil {
		t.Fatal(err)
	}
	return threads
}

func copyData(t *testing.T) {
	dirs := [...]string{"/tmp/threadtest", "/tmp/threadtest/pkt", "/tmp/threadtest/idx"}
	testdata := map[string]string{
		"../testdata/PKT0/dhcp": "/tmp/threadtest/pkt",
		"../testdata/IDX0/dhcp": "/tmp/threadtest/idx",
	}
	for dir := range dirs {
		mkdir := exec.Command("mkdir", dirs[dir])
		if err := mkdir.Run(); err != nil {
			t.Fatal(err)
		}
	}
	for src, dst := range testdata {
		cp := exec.Command("cp", "-rf", src, dst)
		if err := cp.Run(); err != nil {
			t.Fatal(err)
		}
	}
}

func rmData(t *testing.T) {
	os.RemoveAll("/tmp/threadtest")
}

type requestTest func(
	method string,
	path string,
	headers map[string]string,
	body string,
) *httptest.ResponseRecorder

func newRequestTest(t *testing.T, handle http.Handler) requestTest {
	return func(
		method string,
		path string,
		headers map[string]string,
		body string,
	) *httptest.ResponseRecorder {

		req, err := http.NewRequest(
			method,
			path,
			strings.NewReader(body),
		)
		if err != nil {
			t.Errorf("%v", err)
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		w := httptest.NewRecorder()
		handle.ServeHTTP(w, req)
		return w
	}
}

func TestExportDebugHandlers(t *testing.T) {
	copyData(t)
	defer rmData(t)
	m := http.DefaultServeMux
	threads := createThreads(t)
	threads[0].SyncFiles()
	threads[0].ExportDebugHandlers(m)
	r := newRequestTest(t, m)
	var httpTests = []struct {
		method  string
		url     string
		header  map[string]string
		body    string
		code    int
		byteLen int
	}{
		{
			"GET",
			"/debug/t0/index?name=dhcp&start=00&finish=FF",
			map[string]string{"Content-Type": "text/plain"},
			"",
			200,
			141,
		},
		{
			"GET",
			"/debug/t0/packets?name=dhcp",
			map[string]string{"Content-Type": "application/octet-stream"},
			"",
			200,
			1572,
		},
		{
			"GET",
			"/debug/t0/positions?name=dhcp",
			map[string]string{"Content-Type": "text/plain"},
			"port 67",
			200,
			51,
		},
	}
	for _, test := range httpTests {
		got := r(test.method, test.url, test.header, test.body)
		if got.Code != test.code {
			t.Errorf("http request failed. want: %v\ngot: %v\n", test.code, got.Code)
		}
		if got.Body.Len() != test.byteLen {
			t.Errorf("wrong number of bytes. want: %v\ngot: %v\n", got.Body.Len())
		}
	}
}
