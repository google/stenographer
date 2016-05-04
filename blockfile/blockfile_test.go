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

package blockfile

import (
	"reflect"
	"testing"

	"golang.org/x/net/context"

	"github.com/google/stenographer/base"
	"github.com/google/stenographer/filecache"
	"github.com/google/stenographer/query"
)

var ctx = context.Background()

const (
	filename = "../testdata/PKT0/dhcp"
)

func testBlockFile(t *testing.T, filename string) *BlockFile {
	blk, err := NewBlockFile(filename, filecache.NewCache(10))
	if err != nil {
		t.Fatal(err)
	}
	return blk
}

func TestPositions(t *testing.T) {
	blk := testBlockFile(t, filename)
	defer blk.Close()
	for _, test := range []struct {
		// test struct
		query string
		want  base.Positions
	}{
		// tests
		{"port 67", base.Positions{1048624, 1049024, 1049448, 1049848}},
		{"port 69", nil},
	} {
		// code to run single test
		if q, err := query.NewQuery(test.query); err != nil {
			t.Fatal(err)
		} else if got, err := blk.Positions(ctx, q); err != nil {
			t.Fatal(err)
		} else if !reflect.DeepEqual(got, test.want) {
			t.Errorf("wrong packet positions.\nwant: %v\n got: %v\n", test.want, got)
		}
	}
}
