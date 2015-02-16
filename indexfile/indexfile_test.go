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

package indexfile

import (
	"bytes"
	"encoding/hex"
	"github.com/google/stenographer/base"
	"golang.org/x/net/context"
	"reflect"
	"testing"
)

var ctx = context.Background()

func testIndexFile(t *testing.T, filename string) *IndexFile {
	idx, err := NewIndexFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

func TestValidIPPositions(t *testing.T) {
	idx := testIndexFile(t, "../testdata/IDX0/dhcp")
	validPositions := base.Positions{1049024, 1049848}
	positions, err := idx.IPPositions(ctx, parseIP("192.168.0.1"), parseIP("192.168.0.254"))
	if !reflect.DeepEqual(validPositions, positions) {
		t.Fatalf("missing IP positions.\nwant: %v\n got: %v\n err:", validPositions, positions, err)
	}
	idx.Close()
}

func TestInvalidIPPositions(t *testing.T) {
	idx := testIndexFile(t, "../testdata/IDX0/dhcp")
	positions, err := idx.IPPositions(ctx, parseIP("10.0.0.1"), parseIP("10.0.0.254"))
	if positions != nil {
		t.Fatalf("invalid IP positions.\nwant: %v\n got: %v\n err:", nil, positions, err)
	}
	idx.Close()
}

func TestValidMPLSPositions(t *testing.T) {
	idx := testIndexFile(t, "../testdata/IDX0/mpls")
	var validMPLSLabel uint32 = 29
	validPositions := base.Positions{1051144, 1054304, 1054592, 1054736, 1054888, 1055184, 1055328, 1055472, 1055800, 1056824, 1056968}
	positions, err := idx.MPLSPositions(ctx, validMPLSLabel)
	if !reflect.DeepEqual(positions, validPositions) {
		t.Fatalf("missing MPLS positions.\nwant: %v\n got: %v\n err:", validPositions, positions, err)
	}
	idx.Close()
}

func TestInvalidMPLSPositions(t *testing.T) {
	idx := testIndexFile(t, "../testdata/IDX0/mpls")
	var invalidMPLSLabel uint32 = 55
	positions, err := idx.MPLSPositions(ctx, invalidMPLSLabel)
	if positions != nil {
		t.Fatalf("invalid MPLS positions.\nwant: %v\n got: %v\n err:", nil, positions, err)
	}
	idx.Close()
}

func TestValidVLANPositions(t *testing.T) {
	idx := testIndexFile(t, "../testdata/IDX0/vlan")
	var validVLAN uint16 = 7
	validPositions := base.Positions{1123648, 1126248, 1178544, 1192552, 1208680}
	positions, err := idx.VLANPositions(ctx, validVLAN)
	if !reflect.DeepEqual(validPositions, positions) {
		t.Fatalf("missing VLAN positions.\nwant: %v\n got: %v\n err:", validPositions, positions, err)
	}
	idx.Close()
}

func TestInvalidVLANPositions(t *testing.T) {
	idx := testIndexFile(t, "../testdata/IDX0/vlan")
	var validVLAN uint16 = 8
	positions, err := idx.VLANPositions(ctx, validVLAN)
	if positions != nil {
		t.Fatalf("invalid VLAN positions.\nwant: %v\n got: %v\n err:", nil, positions, err)
	}
	idx.Close()
}

func TestValidProtoPositions(t *testing.T) {
	idx := testIndexFile(t, "../testdata/IDX0/dhcp")
	var validDHCPProto byte = '\x11'
	validPositions := base.Positions{1048624, 1049024, 1049448, 1049848}
	positions, err := idx.ProtoPositions(ctx, validDHCPProto)
	if !reflect.DeepEqual(validPositions, positions) {
		t.Fatalf("missing protocol positions.\nwant: %v\n got: %v\n err:", validPositions, positions, err)
	}
	idx.Close()
}

func TestInvalidProtoPositions(t *testing.T) {
	idx := testIndexFile(t, "../testdata/IDX0/dhcp")
	var invalidDHCPProto byte = '\x12'
	positions, err := idx.ProtoPositions(ctx, invalidDHCPProto)
	if positions != nil {
		t.Fatalf("found invalid protocol positions.\nwant: %v\n got: %v\n err:", nil, positions, err)
	}
	idx.Close()
}

func TestValidPortPositions(t *testing.T) {
	idx := testIndexFile(t, "../testdata/IDX0/dhcp")
	var validDHCPPort uint16 = 67
	validPositions := base.Positions{1048624, 1049024, 1049448, 1049848}
	positions, err := idx.PortPositions(ctx, validDHCPPort)
	if !reflect.DeepEqual(validPositions, positions) {
		t.Fatalf("missing port positions.\nwant: %v\n got: %v\n err:", validPositions, positions, err)
	}
	idx.Close()
}

func TestInvalidPortPositions(t *testing.T) {
	idx := testIndexFile(t, "../testdata/IDX0/dhcp")
	var invalidDHCPPort uint16 = 69
	positions, err := idx.PortPositions(ctx, invalidDHCPPort)
	if positions != nil {
		t.Fatalf("missing port positions.\nwant: %v\n got: %v\n err:", nil, positions, err)
	}
	idx.Close()
}

func TestDump(t *testing.T) {
	idx := testIndexFile(t, "../testdata/IDX0/dhcp")
	want := "00\n0111\n013a\n"
	var w bytes.Buffer
	start, _ := hex.DecodeString("00")
	end, _ := hex.DecodeString("02")
	idx.Dump(&w, start, end)
	got := w.String()
	if got != want {
		t.Fatalf("invalid dump.\nwant %q\n got: %q\n", want, got)
	}
}
