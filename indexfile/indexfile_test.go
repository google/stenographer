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

func TestValidName(t *testing.T) {
	filename := "testdata/dhcp_indexfile"
	if idx, idxErr := NewIndexFile(filename); idxErr != nil {
		t.Fatalf("could not open index file %q: %v", filename, idxErr)
	} else {
		name := idx.Name()
		if name != filename {
			t.Fatalf("wrong filename. want: %q, got %q", name, filename)
		} else {
			t.Log(name)
			idx.Close()
		}
	}
}

func TestValidIPPositions(t *testing.T) {
	filename := "testdata/dhcp_indexfile"
	if idx, idxErr := NewIndexFile(filename); idxErr != nil {
		t.Fatalf("could not open index file %q: %v", filename, idxErr)
	} else {
		validStart := "192.168.0.1"
		validEnd := "192.168.0.254"
		validPositions := base.Positions{1049024, 1049848}
		positions, err := idx.IPPositions(ctx, parseIP(validStart), parseIP(validEnd))
		if !reflect.DeepEqual(validPositions, positions) {
			t.Fatalf("missing IP positions. want: %v\n got: %v\n err:", validPositions, positions, err)
		} else {
			t.Log(positions)
			idx.Close()
		}
	}
}

func TestInvalidIPPositions(t *testing.T) {
	filename := "testdata/dhcp_indexfile"
	if idx, idxErr := NewIndexFile(filename); idxErr != nil {
		t.Fatalf("could not open index file %q: %v", filename, idxErr)
	} else {
		invalidStart := "10.0.0.1"
		invalidEnd := "10.0.0.254"
		positions, err := idx.IPPositions(ctx, parseIP(invalidStart), parseIP(invalidEnd))
		if positions != nil {
			t.Fatalf("missing IP positions. want: %v\n got: %v\n err:", nil, positions, err)
		} else {
			t.Log(nil)
			idx.Close()
		}
	}
}

func TestValidMPLSPositions(t *testing.T) {
	filename := "testdata/mpls_indexfile"
	if idx, idxErr := NewIndexFile(filename); idxErr != nil {
		t.Fatalf("could not open index file %q: %v", filename, idxErr)
	} else {
		var validMPLSLabel uint32 = 29
		validPositions := base.Positions{1051144, 1054304, 1054592, 1054736, 1054888, 1055184, 1055328, 1055472, 1055800, 1056824, 1056968}
		positions, err := idx.MPLSPositions(ctx, validMPLSLabel)
		if !reflect.DeepEqual(positions, validPositions) {
			t.Fatalf("missing MPLS positions. want: %v\n got: %v\n err:", validPositions, positions, err)
		} else {
			t.Log(positions)
			idx.Close()
		}
	}
}

func TestInvalidMPLSPositions(t *testing.T) {
	filename := "testdata/mpls_indexfile"
	if idx, idxErr := NewIndexFile(filename); idxErr != nil {
		t.Fatalf("could not open index file %q: %v", filename, idxErr)
	} else {
		var invalidMPLSLabel uint32 = 55
		positions, err := idx.MPLSPositions(ctx, invalidMPLSLabel)
		if positions != nil {
			t.Fatalf("invalid MPLS positions. want: %v\n got: %v\n err:", nil, positions, err)
		} else {
			t.Log(nil)
			idx.Close()
		}
	}
}

func TestValidVLANPositions(t *testing.T) {
	filename := "testdata/vlan_indexfile"
	if idx, idxErr := NewIndexFile(filename); idxErr != nil {
		t.Fatalf("could not open index file %q: %v", filename, idxErr)
	} else {
		var validVLAN uint16 = 7
		validPositions := base.Positions{1123648, 1126248, 1178544, 1192552, 1208680}
		positions, err := idx.VLANPositions(ctx, validVLAN)
		if !reflect.DeepEqual(validPositions, positions) {
			t.Fatalf("missing VLAN positions. want: %v\n got: %v\n err:", validPositions, positions, err)
		} else {
			t.Log(positions)
			idx.Close()
		}
	}
}

func TestInvalidVLANPositions(t *testing.T) {
	filename := "testdata/vlan_indexfile"
	if idx, idxErr := NewIndexFile(filename); idxErr != nil {
		t.Fatalf("could not open index file %q: %v", filename, idxErr)
	} else {
		var validVLAN uint16 = 8
		positions, err := idx.VLANPositions(ctx, validVLAN)
		if positions != nil {
			t.Fatalf("missing VLAN positions. want: %v\n got: %v\n err:", nil, positions, err)
		} else {
			t.Log(nil)
			idx.Close()
		}
	}
}

func TestValidProtoPositions(t *testing.T) {
	filename := "testdata/dhcp_indexfile"
	if idx, idxErr := NewIndexFile(filename); idxErr != nil {
		t.Fatalf("could not open index file %q: %v", filename, idxErr)
	} else {
		var validDhcpProto byte = '\x11'
		validPositions := base.Positions{1048624, 1049024, 1049448, 1049848}
		positions, err := idx.ProtoPositions(ctx, validDhcpProto)
		if !reflect.DeepEqual(validPositions, positions) {
			t.Fatalf("want: %v\n got: %v\n err:", validPositions, positions, err)
		} else {
			t.Log(positions)
			idx.Close()
		}
	}
}

func TestInvalidProtoPositions(t *testing.T) {
	filename := "testdata/dhcp_indexfile"
	if idx, idxErr := NewIndexFile(filename); idxErr != nil {
		t.Fatalf("could not open index file %q: %v", filename, idxErr)
	} else {
		var invalidDhcpProto byte = '\x12'
		positions, err := idx.ProtoPositions(ctx, invalidDhcpProto)
		if positions != nil {
			t.Fatalf("want: %v\n got: %v\n err:", nil, positions, err)
		} else {
			t.Log(nil)
			idx.Close()
		}
	}
}

func TestValidPortPositions(t *testing.T) {
	filename := "testdata/dhcp_indexfile"
	if idx, idxErr := NewIndexFile(filename); idxErr != nil {
		t.Fatalf("could not open index file %q: %v", filename, idxErr)
	} else {
		var validDhcpPort uint16 = 67
		validPositions := base.Positions{1048624, 1049024, 1049448, 1049848}
		positions, err := idx.PortPositions(ctx, validDhcpPort)
		if !reflect.DeepEqual(validPositions, positions) {
			t.Fatalf("want: %v\n got: %v\n err:", validPositions, positions, err)
		} else {
			t.Log(positions)
			idx.Close()
		}
	}
}

func TestInvalidPortPositions(t *testing.T) {
	filename := "testdata/dhcp_indexfile"
	if idx, idxErr := NewIndexFile(filename); idxErr != nil {
		t.Fatalf("could not open index file %q: %v", filename, idxErr)
	} else {
		var invalidDhcpPort uint16 = 69
		positions, err := idx.PortPositions(ctx, invalidDhcpPort)
		if positions != nil {
			t.Fatalf("want: %v\n got: %v\n err:", nil, positions, err)
		} else {
			t.Log(nil)
			idx.Close()
		}
	}
}

func TestDump(t *testing.T) {
	filename := "testdata/dhcp_indexfile"
	if idx, idxErr := NewIndexFile(filename); idxErr != nil {
		t.Fatalf("could not open index file %q: %v", filename, idxErr)
	} else {
		want := "00\n0111\n013a\n"
		var w bytes.Buffer
		start, _ := hex.DecodeString("00")
		end, _ := hex.DecodeString("02")
		idx.Dump(&w, start, end)
		got := w.String()
		if got != want {
			t.Fatalf("want %q\n got: %q\n", want, got)
		} else {
			t.Log(got)
			idx.Close()
		}
	}
}
