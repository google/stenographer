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

// Package indexfile provides methods for querying stenotype indexes to find the
// blockfile positions of packets.
package indexfile

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"code.google.com/p/leveldb-go/leveldb/table"
	"github.com/google/stenographer/base"
	"golang.org/x/net/context"
)

var v = base.V // verbose logging locally.

type IndexFile struct {
	name string
	ss   *table.Reader
}

// IndexPathFromBlockfilePath returns the path to an index file based on the path to a
// block file.
func IndexPathFromBlockfilePath(p string) string {
	return strings.Replace(p, "PKT", "IDX", 1)
}

// BlockfilePathFromIndexPath returns the path to a block file based on the path to an
// index file.
func BlockfilePathFromIndexPath(p string) string {
	return strings.Replace(p, "IDX", "PKT", 1)
}

// NewIndexFile returns a new handle to the named index file.
func NewIndexFile(filename string) (*IndexFile, error) {
	v(1, "opening index %q", filename)
	base.StartRead()
	defer base.FinishRead()
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file %q: %v", filename, err)
	}
	ss := table.NewReader(f, nil)
	if *base.VerboseLogging >= 4 {
		iter := ss.Find([]byte{}, nil)
		v(4, "=== %q ===", filename)
		for iter.Next() {
			v(4, "  %v %v", iter.Key(), iter.Value())
		}
		v(4, "  ERR: %v", iter.Close())
	}
	index := &IndexFile{ss: ss, name: filename}
	return index, nil
}

// Name returns the name of the file underlying this index.
func (i *IndexFile) Name() string {
	return i.name
}

// IPPositions returns the positions in the block file of all packets with IPs
// between the given ranges.  Both IPs must be 4 or 16 bytes long, both must be
// the same length, and from must be <= to.
func (i *IndexFile) IPPositions(ctx context.Context, from, to net.IP) (base.Positions, error) {
	var version byte
	switch {
	case len(from) != len(to):
		return nil, fmt.Errorf("IP length mismatch")
	case bytes.Compare(from, to) > 0:
		return nil, fmt.Errorf("from IP greater than to IP")
	case len(from) == 16:
		version = 6
	case len(from) == 4:
		version = 4
	default:
		return nil, fmt.Errorf("Invalid IP length")
	}
	return i.positions(
		ctx,
		append([]byte{version}, []byte(from)...),
		append([]byte{version}, []byte(to)...))
}

// ProtoPositions returns the positions in the block file of all packets with
// the give IP protocol number.
func (i *IndexFile) ProtoPositions(ctx context.Context, proto byte) (base.Positions, error) {
	return i.positionsSingleKey(ctx, []byte{1, proto})
}

// ProtoPositions returns the positions in the block file of all packets with
// the give port number (TCP or UDP).
func (i *IndexFile) PortPositions(ctx context.Context, port uint16) (base.Positions, error) {
	var buf [3]byte
	binary.BigEndian.PutUint16(buf[1:], port)
	buf[0] = 2
	return i.positionsSingleKey(ctx, buf[:])
}

func preceedingBytes(b []byte) (out []byte) {
	out = make([]byte, len(b))
	copy(out, b)
	for i := len(b) - 1; i >= 0; i-- {
		if out[i] == 0 {
			out[i] = 0xff
		} else {
			out[i]--
			return
		}
	}
	return nil
}

// Dump writes out a debug version of the entire index to the given writer.
func (i *IndexFile) Dump(out io.Writer, start, finish []byte) {
	for iter := i.ss.Find(start, nil); iter.Next() && bytes.Compare(iter.Key(), finish) <= 0; {
		fmt.Fprintf(out, "%v\t%v\n", hex.EncodeToString(iter.Key()), hex.EncodeToString(iter.Value()))
	}
}

func (i *IndexFile) positions(ctx context.Context, from, to []byte) (out base.Positions, _ error) {
	v(4, "%q multi key iterator %v:%v start", i.name, from, to)
	base.StartRead()
	defer base.FinishRead()
	iter := i.ss.Find(preceedingBytes(from), nil)
	found := false
	last := make([]byte, len(from))
	copy(last, from)
	var current base.Positions
	for iter.Next() && !base.ContextDone(ctx) {
		if !found && bytes.Compare(iter.Key(), from) < 0 {
			continue
		}
		if to != nil && bytes.Compare(iter.Key(), to) > 0 {
			break
		}
		if bytes.Compare(iter.Key(), last) != 0 {
			out = out.Union(current)
			current = base.Positions{}
			copy(last, iter.Key())
		}
		pos := binary.BigEndian.Uint32(iter.Value())
		current = append(current, int64(pos))
	}
	if err := ctx.Err(); err != nil {
		v(4, "%q multi key iterator context err: %v", i.name, err)
		return nil, err
	}
	out = out.Union(current)
	v(4, "%q multi key iterator done, got %d", i.name, len(out))
	if err := iter.Close(); err != nil {
		v(4, "%q multi key iterator err=%v", i.name, err)
		return nil, err
	}
	return out, nil
}
func (i *IndexFile) positionsSingleKey(ctx context.Context, key []byte) (base.Positions, error) {
	return i.positions(ctx, key, key)
}

func parseIP(in string) net.IP {
	ip := net.ParseIP(in)
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return ip
}

func (i *IndexFile) Close() error {
	return i.ss.Close()
}
