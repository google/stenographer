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
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sort"

	"github.com/google/stenographer/base"
	"github.com/google/stenographer/sstable"
)

var v = base.V // verbose logging locally.

type IndexFile struct {
	name string
	ss   *sstable.Table
}

// IndexPathFromPath returns the path to an index file based on the path to a
// block file.
func IndexPathFromPath(p string) string {
	return strings.Replace(p, "PKT", "IDX", 1)
}

// NewIndexFile returns a new handle to the named index file.
func NewIndexFile(filename string) (*IndexFile, error) {
	v(1, "opening index %q", filename)
	ss, err := sstable.NewTable(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening index %q: %v", filename, err)
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
func (i *IndexFile) IPPositions(from, to net.IP) (base.Positions, error) {
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
		append([]byte{version}, []byte(from)...),
		append([]byte{version}, []byte(to)...))
}

// ProtoPositions returns the positions in the block file of all packets with
// the give IP protocol number.
func (i *IndexFile) ProtoPositions(proto byte) (base.Positions, error) {
	return i.positionsSingleKey([]byte{1, proto})
}

// ProtoPositions returns the positions in the block file of all packets with
// the give port number (TCP or UDP).
func (i *IndexFile) PortPositions(port uint16) (base.Positions, error) {
	var buf [3]byte
	binary.BigEndian.PutUint16(buf[1:], port)
	buf[0] = 2
	return i.positionsSingleKey(buf[:])
}

// Dump writes out a debug version of the entire index to the given writer.
func (i *IndexFile) Dump(out io.Writer) {
	iter := i.ss.Iter([]byte{})
	for iter.Next() {
		fmt.Fprintf(out, "%v %v\n", iter.Key(), iter.Value())
	}
	if err := iter.Err(); err != nil {
		fmt.Fprintf(out, "ERR: %v", err)
	}
}

func (i *IndexFile) positionsSingleKey(key []byte) (base.Positions, error) {
	var sortedPos base.Positions
	v(4, "%q single key iterator %+v start", i.name, key)
	iter := i.ss.Iter(key)
	count := int64(0)
	for iter.Next() {
		if !bytes.Equal(key, iter.Key()) {
			v(4, "%q single key iterator high key %v", i.name, iter.Key())
			break
		}
		v(4, "%q single key iterator %v=%v", i.name, iter.Key(), iter.Value())
		pos := binary.BigEndian.Uint32(iter.Value())
		sortedPos = append(sortedPos, int64(pos))
		count++
	}
	v(4, "%q single key iterator done", i.name)
	if err := iter.Err(); err != nil {
		v(4, "%q single key iterator err=%v", i.name, err)
		return nil, err
	}
	return sortedPos, nil
}

func (i *IndexFile) positions(from, to []byte) (base.Positions, error) {
	if bytes.Equal(from, to) {
		return i.positionsSingleKey(from)
	}
	v(4, "%q multi key iterator %v:%v start", i.name, from, to)
	iter := i.ss.Iter(from)
	positions := map[uint32]bool{}
	count := int64(0)
	for iter.Next() {
		if bytes.Compare(iter.Key(), from) > 0 {
			v(4, "%q multi key iterator high key %v", i.name, iter.Key())
			break
		}
		v(4, "%q multi key iterator %v=%v", i.name, iter.Key(), iter.Value())
		pos := binary.BigEndian.Uint32(iter.Value())
		positions[pos] = true
		count++
	}
	v(4, "%q multi key iterator done", i.name)
	if err := iter.Err(); err != nil {
		v(4, "%q multi key iterator err=%v", i.name, err)
		return nil, err
	}
	sortedPos := make(base.Positions, 0, len(positions))
	for pos := range positions {
		sortedPos = append(sortedPos, int64(pos))
	}
	sort.Sort(sortedPos)
	return sortedPos, nil
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
