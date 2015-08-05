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

	"github.com/golang/leveldb/table"
	"github.com/google/stenographer/base"
	"github.com/google/stenographer/stats"
	"golang.org/x/net/context"
)

var (
	v                 = base.V // verbose logging locally.
	indexReadNanos    = stats.S.Get("indexfile_read_nanos")
	indexReads        = stats.S.Get("indexfile_reads")
	indexCurrentReads = stats.S.Get("indexfile_current_reads")
)

// Major version number of the file format that we support.
const majorVersionNumber = 2

// IndexFile wraps a stenotype index, allowing it to be queried.
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
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file %q: %v", filename, err)
	}
	ss := table.NewReader(f, nil)
	if versions, err := ss.Get([]byte{0}, nil); err != nil {
		return nil, fmt.Errorf("invalid index file %q missing versions record: %v", filename, err)
	} else if len(versions) != 8 {
		return nil, fmt.Errorf("invalid index file %q invalid versions record: %v", filename, versions)
	} else if major, minor := binary.BigEndian.Uint32(versions[:4]), binary.BigEndian.Uint32(versions[4:]); major != majorVersionNumber {
		return nil, fmt.Errorf("invalid index file %q: version mismatch, want %d got %d", filename, majorVersionNumber, major)
	} else {
		v(3, "index file %q has file format version %d:%d", filename, major, minor)
	}
	if *base.VerboseLogging >= 10 {
		iter := ss.Find([]byte{}, nil)
		v(4, "=== %q ===", filename)
		for iter.Next() {
			v(4, "  %v", iter.Key())
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

// PortPositions returns the positions in the block file of all packets with
// the give port number (TCP or UDP).
func (i *IndexFile) PortPositions(ctx context.Context, port uint16) (base.Positions, error) {
	var buf [3]byte
	binary.BigEndian.PutUint16(buf[1:], port)
	buf[0] = 2
	return i.positionsSingleKey(ctx, buf[:])
}

// VLANPositions returns the positions in the block file of all packets with
// the given VLAN number.
func (i *IndexFile) VLANPositions(ctx context.Context, port uint16) (base.Positions, error) {
	var buf [3]byte
	binary.BigEndian.PutUint16(buf[1:], port)
	buf[0] = 3
	return i.positionsSingleKey(ctx, buf[:])
}

// MPLSPositions returns the positions in the block file of all packets with
// the given MPLS number.
func (i *IndexFile) MPLSPositions(ctx context.Context, mpls uint32) (base.Positions, error) {
	var buf [5]byte
	binary.BigEndian.PutUint32(buf[1:], mpls)
	buf[0] = 5
	return i.positionsSingleKey(ctx, buf[:])
}

// Dump writes out a debug version of the entire index to the given writer.
func (i *IndexFile) Dump(out io.Writer, start, finish []byte) {
	for iter := i.ss.Find(start, nil); iter.Next() && bytes.Compare(iter.Key(), finish) <= 0; {
		fmt.Fprintf(out, "%v\n", hex.EncodeToString(iter.Key()))
	}
}

// positions returns a set of positions to look for packets, based on a
// lookup of all blockfile positions stored between (inclusively) index
// keys 'from' and 'to'.
func (i *IndexFile) positions(ctx context.Context, from, to []byte) (out base.Positions, _ error) {
	v(4, "%q multi key iterator %v:%v start", i.name, from, to)
	if len(from) != len(to) {
		return nil, fmt.Errorf("invalid from/to lengths don't match: %v %v", from, to)
	}
	indexCurrentReads.Increment()
	defer func() {
		indexCurrentReads.IncrementBy(-1)
		indexReads.Increment()
	}()
	defer indexReadNanos.NanoTimer()()
	iter := i.ss.Find(from, nil)
	for iter.Next() && !base.ContextDone(ctx) {
		if to != nil && bytes.Compare(iter.Key(), to) > 0 {
			v(4, "%q multi key iterator %v:%v hit limit with %v", i.name, from, to, iter.Key())
			break
		}
		current := make(base.Positions, len(iter.Value())/4)
		for i := 0; i < len(iter.Value()); i += 4 {
			current[i/4] = int64(binary.BigEndian.Uint32(iter.Value()[i : i+4]))
		}
		v(4, "%q multi key iterator got in-iter union of length %d for %v", i.name, len(current), iter.Key())
		if out == nil {
			out = current
		} else {
			out = out.Union(current)
		}
	}
	if err := ctx.Err(); err != nil {
		v(4, "%q multi key iterator context err: %v", i.name, err)
		return nil, err
	}
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

// Close the indexfile.
func (i *IndexFile) Close() error {
	return i.ss.Close()
}
