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

// Package preadlib provides helper functionality for reading packet data out of
// files in the format they're dumped by pdump.
package preadlib

import (
	"bytes"
	"container/heap"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcapgo"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/table"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// #include <linux/if_packet.h>
import "C"

var verboseLogging = flag.Int("v", 0, "log many verbose logs")

// V provides verbose logging which can be turned on/off with the -v flag.
func V(level int, fmt string, args ...interface{}) {
	if *verboseLogging >= level {
		log.Printf(fmt, args...)
	}
}

const SnapLen = 65536

type BlockFile struct {
	name string
	f    io.ReaderAt
	i    *Index
}

func NewBlockFile(filename string) (*BlockFile, error) {
	V(1, "opening blockfile %q", filename)
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open %q: %v", filename, err)
	}
	i, err := NewIndex(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open index for %q: %v", filename, err)
	}
	return &BlockFile{f: f, i: i, name: filename}, nil
}

func (b *BlockFile) ReadPacket(pos int64, ci *gopacket.CaptureInfo) ([]byte, error) {
	var dataBuf [28]byte
	// 28 bytes actually isn't the entire packet header, but it's all the fields
	// that we care about.
	_, err := b.f.ReadAt(dataBuf[:], pos)
	if err != nil {
		return nil, err
	}
	pkt := (*C.struct_tpacket3_hdr)(unsafe.Pointer(&dataBuf[0]))
	*ci = gopacket.CaptureInfo{
		Timestamp:     time.Unix(int64(pkt.tp_sec), int64(pkt.tp_nsec)),
		Length:        int(pkt.tp_len),
		CaptureLength: int(pkt.tp_snaplen),
	}
	out := make([]byte, ci.CaptureLength)
	pos += int64(pkt.tp_mac)
	_, err = b.f.ReadAt(out, pos)
	return out, err
}

type Int64Slice []int64

func (a Int64Slice) Less(i, j int) bool {
	return a[i] < a[j]
}
func (a Int64Slice) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
func (a Int64Slice) Len() int {
	return len(a)
}

func (a Int64Slice) Union(b Int64Slice) (out Int64Slice) {
	out = make(Int64Slice, 0, len(a)+len(b)/2)
	ib := 0
	for _, pos := range a {
		for ib < len(b) && b[ib] < pos {
			out = append(out, b[ib])
			ib++
		}
		if ib < len(b) && b[ib] == pos {
			ib++
		}
		out = append(out, pos)
	}
	out = append(out, b[ib:]...)
	return out
}

func (a Int64Slice) Intersect(b Int64Slice) (out Int64Slice) {
	out = make(Int64Slice, 0, len(a)/2)
	ib := 0
	for _, pos := range a {
		for ib < len(b) && b[ib] < pos {
			ib++
		}
		if ib < len(b) && b[ib] == pos {
			out = append(out, pos)
			ib++
		}
	}
	return out
}

type Index struct {
	name string
	f    *table.Reader
}

func NewIndex(filename string) (*Index, error) {
	filename = filepath.Join(
		filepath.Dir(filename),
		"INDEX",
		filepath.Base(filename))
	V(1, "opening index %q", filename)
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening index %q: %v", filename, err)
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("error stat-ing file %q: %v", filename, err)
	}
	opts := &opt.Options{}
	reader := table.NewReader(
		f,
		stat.Size(),
		nil,
		util.NewBufferPool(opts.GetBlockSize()*5),
		opts)
	index := &Index{f: reader, name: filename}
	if _, err := index.positionsSingleKey([]byte{}); err != nil {
		return nil, fmt.Errorf("unable to read from table %q: %v", filename, err)
	}
	f = nil // File shouldn't be closed.
	return index, nil
}

func (i *Index) IPPositions(from, to net.IP) (Int64Slice, error) {
	var version byte
	switch {
	case len(from) != len(to):
		return nil, fmt.Errorf("IP length mismatch")
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

func (i *Index) ProtoPositions(proto byte) (Int64Slice, error) {
	return i.positionsSingleKey([]byte{1, proto})
}

func (i *Index) PortPositions(port uint16) (Int64Slice, error) {
	var buf [3]byte
	binary.BigEndian.PutUint16(buf[1:], port)
	buf[0] = 2
	return i.positionsSingleKey(buf[:])
}

var readOpts = &opt.ReadOptions{Strict: opt.StrictAll}

func (i *Index) positionsSingleKey(key []byte) (Int64Slice, error) {
	var sortedPos Int64Slice
	iter := i.f.NewIterator(&util.Range{Start: key, Limit: append(key, 0)}, readOpts)
	count := int64(0)
	for iter.Next() {
		pos := binary.BigEndian.Uint32(iter.Value())
		sortedPos = append(sortedPos, int64(pos))
		count++
	}
	if err := iter.Error(); err != nil {
		return nil, err
	}
	return sortedPos, nil
}

func (i *Index) positions(from, to []byte) (Int64Slice, error) {
	if bytes.Equal(from, to) {
		return i.positionsSingleKey(from)
	}
	iter := i.f.NewIterator(&util.Range{Start: from, Limit: append(to, 0)}, readOpts)
	positions := map[uint32]bool{}
	count := int64(0)
	for iter.Next() {
		pos := binary.BigEndian.Uint32(iter.Value())
		positions[pos] = true
		count++
	}
	if err := iter.Error(); err != nil {
		return nil, err
	}
	sortedPos := make(Int64Slice, 0, len(positions))
	for pos := range positions {
		sortedPos = append(sortedPos, int64(pos))
	}
	sort.Sort(sortedPos)
	return sortedPos, nil
}

func parseIP(in string) net.IP {
	ip := net.ParseIP(in)
	if ip == nil {
		log.Fatalf("invalid IP: %q", in)
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return ip
}

func (i *Index) lookupSingleArgument(arg string) Int64Slice {
	parts := strings.Split(arg, "=")
	if len(parts) != 2 {
		log.Fatalf("invalid arg: %q", arg)
	}
	var pos Int64Slice
	var err error
	switch parts[0] {
	case "ip":
		ips := strings.Split(parts[1], "-")
		var from, to net.IP
		switch len(ips) {
		case 1:
			from = parseIP(ips[0])
			to = from
		case 2:
			from = parseIP(ips[0])
			to = parseIP(ips[1])
		default:
			log.Fatalf("invalid #IPs: %q", arg)
		}
		pos, err = i.IPPositions(from, to)
	case "port":
		port, perr := strconv.Atoi(parts[1])
		if err != nil {
			log.Fatalf("invalid port %q: %v", parts[1], perr)
		}
		pos, err = i.PortPositions(uint16(port))
	case "protocol":
		proto, perr := strconv.Atoi(parts[1])
		if err != nil {
			log.Fatalf("invalid proto %q: %v", parts[1], perr)
		}
		pos, err = i.ProtoPositions(byte(proto))
	}
	if err != nil {
		log.Fatalf("error getting positions (%q): %v", arg, err)
	}
	return pos
}

func (i *Index) lookupUnionArguments(arg string) Int64Slice {
	args := strings.Split(arg, "|")
	var positions Int64Slice
	c := make(chan Int64Slice)
	for _, a := range args {
		a := a
		go func() { c <- i.lookupSingleArgument(a) }()
	}

	first := true
	for _ = range args {
		pos := <-c
		if first {
			positions = pos
			first = false
		} else {
			positions = positions.Union(pos)
		}
		V(3, "%q %p U(%v) -> %v", i.name, &first, len(pos), len(positions))
	}
	return positions
}

func (i *Index) Lookup(in string) Int64Slice {
	actualArgs := strings.Fields(in)
	c := make(chan Int64Slice)
	for _, arg := range actualArgs {
		arg := arg
		go func() { c <- i.lookupUnionArguments(arg) }()
	}
	var positions Int64Slice
	first := true
	for _ = range actualArgs {
		pos := <-c
		if first {
			positions = pos
			first = false
		} else {
			positions = positions.Intersect(pos)
		}
		V(3, "%q %p U(%v) -> %v", i.name, &first, len(pos), len(positions))
	}
	return positions
}

type Packet struct {
	Data []byte
	gopacket.CaptureInfo
}

func (b *BlockFile) Lookup(in string) <-chan Packet {
	c := make(chan Packet, 10000)
	go func() {
		var ci gopacket.CaptureInfo
		positions := b.i.Lookup(in)
		V(2, "blockfile %q reading %v packets", b.name, len(positions))
		for _, pos := range positions {
			buffer, err := b.ReadPacket(pos, &ci)
			if err != nil {
				log.Fatalf("error reading packet from %q @ %v: %v", b.name, pos, err)
			}
			c <- Packet{
				Data:        buffer,
				CaptureInfo: ci,
			}
		}
		close(c)
	}()
	return c
}

func PacketsToFile(in <-chan Packet, out io.Writer) error {
	w := pcapgo.NewWriter(out)
	w.WriteFileHeader(SnapLen, layers.LinkTypeEthernet)
	count := 0
	for p := range in {
		if err := w.WritePacket(p.CaptureInfo, p.Data); err != nil {
			// This can happen if our pipe is broken, and we don't want to blow stack
			// traces all over our users when that happens, so Error/Exit instead of
			// Fatal.
			return fmt.Errorf("error writing packet: %v", err)
		}
		count++
	}
	return nil
}

type indexedPacket struct {
	Packet
	i int
}
type packetHeap []indexedPacket

func (p packetHeap) Len() int            { return len(p) }
func (p packetHeap) Swap(i, j int)       { p[i], p[j] = p[j], p[i] }
func (p packetHeap) Less(i, j int) bool  { return p[i].Timestamp.Before(p[j].Timestamp) }
func (p *packetHeap) Push(x interface{}) { *p = append(*p, x.(indexedPacket)) }
func (p *packetHeap) Pop() (x interface{}) {
	index := len(*p) - 1
	*p, x = (*p)[:index], (*p)[index]
	return
}

func MergePackets(in []<-chan Packet) <-chan Packet {
	out := make(chan Packet)
	go func() {
		var h packetHeap
		for i, c := range in {
			for p := range c {
				heap.Push(&h, indexedPacket{Packet: p, i: i})
			}
		}
		V(1, "merged packet stream has %v packets", len(h))
		for h.Len() > 0 {
			p := heap.Pop(&h).(indexedPacket)
			out <- p.Packet
			newP, ok := <-in[p.i]
			if ok {
				heap.Push(&h, indexedPacket{Packet: newP, i: p.i})
			}
		}
		close(out)
	}()
	return out
}
