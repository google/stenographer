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
	"github.com/google/stenographer/base"
	"github.com/google/stenographer/query"
	"golang.org/x/net/context"
	"reflect"
	"testing"
)

var ctx = context.Background()

const (
	filename = "../testdata/PKT0/dhcp"
)

func TestValidPositions(t *testing.T) {
	if blk, blkErr := NewBlockFile(filename); blkErr != nil {
		t.Fatalf("could not open block file %v: %v", filename, blkErr)
	} else {
		positions := base.Positions{1048624, 1049024, 1049448, 1049848}
		q, _ := query.NewQuery("port 67")
		received, err := blk.Positions(ctx, q)
		if err != nil {
			t.Fatalf("query error: %v", err)
		}
		if !reflect.DeepEqual(positions, received) {
			t.Fatalf("wrong packet positions.\nwant: %v\n got: %v\n", positions, received)
		} else {
			t.Log(positions)
		}
	}
}

func TestInvalidPositions(t *testing.T) {
	if blk, blkErr := NewBlockFile(filename); blkErr != nil {
		t.Fatalf("could not open block file %v: %v", filename, blkErr)
	} else {
		q, _ := query.NewQuery("port 69")
		received, err := blk.Positions(ctx, q)
		if err != nil {
			t.Fatalf("query error: %v", err)
		}
		if received != nil {
			t.Fatalf("wrong packet positions.\nwant: %v\n got: %v\n", nil, received)
		} else {
			t.Log(nil)
		}
	}
}

func TestValidLookup(t *testing.T) {
	if blk, blkErr := NewBlockFile(filename); blkErr != nil {
		t.Fatalf("could not open block file %v: %v", filename, blkErr)
	} else {
		q, _ := query.NewQuery("port 67")
		out := base.NewPacketChan(100)
		packets := 4
		blk.Lookup(ctx, q, out)
		received := len(out.Receive())
		if received != packets {
			t.Fatal("wrong number of packets.\nwant: %v\n got: %v\n", packets, received)
		} else {
			t.Log(received)
		}
	}
}

func TestInvalidLookup(t *testing.T) {
	if blk, blkErr := NewBlockFile(filename); blkErr != nil {
		t.Fatalf("could not open block file %v: %v", filename, blkErr)
	} else {
		q, _ := query.NewQuery("port 22")
		out := base.NewPacketChan(100)
		packets := 0
		blk.Lookup(ctx, q, out)
		received := len(out.Receive())
		if received != packets {
			t.Fatal("wrong number of packets.\nwant: %v\n got: %v\n", packets, received)
		} else {
			t.Log(received)
		}
	}
}
