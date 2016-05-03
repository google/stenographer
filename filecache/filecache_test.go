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

package filecache

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestCache(t *testing.T) {
	d, err := ioutil.TempDir("", "filecache_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(d)
	paths := make([]string, 100)
	for i := 0; i < 100; i++ {
		intstr := fmt.Sprintf("%d", i)
		paths[i] = filepath.Join(d, intstr)
		if err := ioutil.WriteFile(paths[i], []byte(intstr), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := NewCache(10)
	var b [1]byte
	for i := 0; i < 100; i++ {
		if _, err := c.Open(paths[i]).ReadAt(b[:], 0); err != nil {
			t.Fatalf("opening/reading %q: %v", paths[i], err)
		}
	}
	for i := 0; i < 100; i++ {
		if _, err := c.Open(paths[i]).ReadAt(b[:], 0); err != nil {
			t.Fatalf("opening/reading %q: %v", paths[i], err)
		}
	}
}
