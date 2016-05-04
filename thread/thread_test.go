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
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/stenographer/config"
	"github.com/google/stenographer/filecache"
)

const (
	baseDir       = "/threadtest/"
	pktDir        = "/threadtest/pkt/"
	idxDir        = "/threadtest/idx/"
	testBlockFile = "../testdata/PKT0/dhcp"
	testIndexFile = "../testdata/IDX0/dhcp"
)

func createThreads(t *testing.T, tempDir string) []*Thread {
	var tc = []config.ThreadConfig{
		{tempDir + pktDir, tempDir + idxDir, 10, 10},
	}
	threads, err := Threads(tc, tempDir+baseDir, filecache.NewCache(10))
	if err != nil {
		t.Fatal(err)
	}
	return threads
}

func copyData(t *testing.T, tempDir string) {
	dirs := [...]string{tempDir + pktDir, tempDir + idxDir}
	testdata := map[string]string{
		testBlockFile: tempDir + pktDir,
		testIndexFile: tempDir + idxDir,
	}
	for _, dir := range dirs {
		err := os.MkdirAll(dir, os.FileMode(0755))
		if err != nil {
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

func rmData(t *testing.T, tempDir string) {
	os.RemoveAll(tempDir)
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
	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	copyData(t, tempDir)
	defer rmData(t, tempDir)
	m := http.DefaultServeMux
	threads := createThreads(t, tempDir)
	if threadLen := len(threads); threadLen != 1 {
		t.Errorf("wrong number of threads: want: %v\ngot: %v\n", 1, threadLen)
	}
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
		out     string
	}{
		{
			"GET",
			"/debug/t0/index?name=dhcp&start=00&finish=FF",
			map[string]string{"Content-Type": "text/plain"},
			"",
			200,
			141,
			"00\n0111\n013a\n020043\n020044\n0400000000\n04c0a80001\n04c0a8000a\n04ffffffff\n06fe800000000000003070b6fffe116f27\n06ff020000000000000000000000000002\n",
		},
		{
			"GET",
			"/debug/t0/packets?name=dhcp",
			map[string]string{"Content-Type": "application/octet-stream"},
			"",
			200,
			1572,
			"d4c3b2a10200040000000000000000000000010001000000eb00dc5452d90a004600000046000000",
		},
		{
			"GET",
			"/debug/t0/positions?name=dhcp",
			map[string]string{"Content-Type": "text/plain"},
			"port 67",
			200,
			51,
			"POSITIONS:\n\t00100030\n\t001001c0\n\t00100368\n\t001004f8\n",
		},
	}
	for _, test := range httpTests {
		got := r(test.method, test.url, test.header, test.body)
		if got.Code != test.code {
			t.Errorf("http request failed. want: %v\ngot: %v\n", test.code, got.Code)
		}
		if test.header["Content-Type"] == "text/plain" {
			if got.Body.String() != test.out {
				t.Errorf("body mismatch. want: %v\ngot: %v\n", test.out, got.Body.String())
			}
		}
		if test.header["Content-Type"] == "application/octet-stream" {
			out := hex.EncodeToString(got.Body.Bytes())
			if !strings.Contains(out, test.out) {
				t.Errorf("body mismatch. want: %v in\ngot: %v\n", test.out, out)
			}
		}
		byteLen := got.Body.Len()
		if byteLen != test.byteLen {
			t.Errorf("wrong number of bytes. want: %v\ngot: %v\n", test.byteLen, byteLen)
		}
	}
}
