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

func TestIPPositions(t *testing.T) {
	idx := testIndexFile(t, "../testdata/IDX0/dhcp")
	defer idx.Close()
	for _, test := range []struct {
		start string
		end   string
		want  base.Positions
	}{
		{"192.168.0.1", "192.168.0.254", base.Positions{1049024, 1049848}},
		{"10.0.0.1", "10.0.0.254", nil},
	} {
		if got, err := idx.IPPositions(ctx, parseIP(test.start), parseIP(test.end)); err != nil {
			t.Fatal(err)
		} else if !reflect.DeepEqual(got, test.want) {
			t.Errorf("wrong IP positions.\nwant: %v\n got: %v\n", test.want, got)
		}
	}
}

func TestMPLSPositions(t *testing.T) {
	idx := testIndexFile(t, "../testdata/IDX0/mpls")
	defer idx.Close()
	for _, test := range []struct {
		label uint32
		want  base.Positions
	}{
		{29, base.Positions{1051144, 1054304, 1054592, 1054736, 1054888, 1055184, 1055328, 1055472, 1055800, 1056824, 1056968}},
		{55, nil},
	} {
		if got, err := idx.MPLSPositions(ctx, test.label); err != nil {
			t.Fatal(err)
		} else if !reflect.DeepEqual(got, test.want) {
			t.Errorf("wrong MPLS positions.\nwant: %v\n got: %v\n", test.want, got)
		}
	}
}

func TestVLANPositions(t *testing.T) {
	idx := testIndexFile(t, "../testdata/IDX0/vlan")
	defer idx.Close()
	for _, test := range []struct {
		id   uint16
		want base.Positions
	}{
		{7, base.Positions{1123648, 1126248, 1178544, 1192552, 1208680}},
		{8, nil},
	} {
		if got, err := idx.VLANPositions(ctx, test.id); err != nil {
			t.Fatal(err)
		} else if !reflect.DeepEqual(got, test.want) {
			t.Errorf("wrong VLAN positions.\nwant: %v\n got: %v\n", test.want, got)
		}
	}
}

func TestProtoPositions(t *testing.T) {
	idx := testIndexFile(t, "../testdata/IDX0/dhcp")
	defer idx.Close()
	for _, test := range []struct {
		proto byte
		want  base.Positions
	}{
		{'\x11', base.Positions{1048624, 1049024, 1049448, 1049848}},
		{'\x12', nil},
	} {
		if got, err := idx.ProtoPositions(ctx, test.proto); err != nil {
			t.Fatal(err)
		} else if !reflect.DeepEqual(got, test.want) {
			t.Errorf("wrong proto positions.\nwant: %v\n got: %v\n", test.want, got)
		}
	}
}

func TestPortPositions(t *testing.T) {
	idx := testIndexFile(t, "../testdata/IDX0/dhcp")
	defer idx.Close()
	for _, test := range []struct {
		port uint16
		want base.Positions
	}{
		{67, base.Positions{1048624, 1049024, 1049448, 1049848}},
		{69, nil},
	} {
		if got, err := idx.PortPositions(ctx, test.port); err != nil {
			t.Fatal(err)
		} else if !reflect.DeepEqual(got, test.want) {
			t.Errorf("wrong proto positions.\nwant: %v\n got: %v\n", test.want, got)
		}
	}
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
