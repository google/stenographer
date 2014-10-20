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
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
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
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return ip
}

func (i *Index) lookupSingleArgument(arg string) (Int64Slice, error) {
	parts := strings.Split(arg, "=")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid arg: %q", arg)
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
			if from == nil {
				return nil, fmt.Errorf("invalid IP %v", ips[0])
			}
			to = from
		case 2:
			from = parseIP(ips[0])
			if from == nil {
				return nil, fmt.Errorf("invalid IP %v", ips[0])
			}
			to = parseIP(ips[1])
			if to == nil {
				return nil, fmt.Errorf("invalid IP %v", ips[1])
			}
		default:
			return nil, fmt.Errorf("invalid #IPs: %q", arg)
		}
		pos, err = i.IPPositions(from, to)
	case "port":
		port, perr := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %v", parts[1], perr)
		}
		pos, err = i.PortPositions(uint16(port))
	case "protocol":
		proto, perr := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid proto %q: %v", parts[1], perr)
		}
		pos, err = i.ProtoPositions(byte(proto))
	}
	if err != nil {
		return nil, fmt.Errorf("error getting positions (%q): %v", arg, err)
	}
	return pos, nil
}

func (i *Index) lookupUnionArguments(arg string) (Int64Slice, error) {
	args := strings.Split(arg, "|")
	var positions Int64Slice
	c := make(chan Int64Slice, len(args))
	errs := make(chan error, len(args))
	for _, a := range args {
		a := a
		go func() {
			pos, err := i.lookupSingleArgument(a)
			c <- pos
			if err != nil {
				errs <- err
			}
		}()
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
	close(errs)
	return positions, <-errs
}

func (i *Index) Lookup(in string) (Int64Slice, error) {
	actualArgs := strings.Fields(in)
	c := make(chan Int64Slice, len(actualArgs))
	errs := make(chan error, len(actualArgs))
	for _, arg := range actualArgs {
		arg := arg
		go func() {
			pos, err := i.lookupUnionArguments(arg)
			c <- pos
			if err != nil {
				errs <- err
			}
		}()
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
	close(errs)
	return positions, <-errs
}

type Packet struct {
	Data []byte
	gopacket.CaptureInfo
}

func (b *BlockFile) Lookup(in string) Packets {
	c := newPackets()
	go func() {
		var ci gopacket.CaptureInfo
		positions, err := b.i.Lookup(in)
		if err != nil {
			c.finish(fmt.Errorf("index lookup failure: %v", err))
			return
		}
		V(2, "blockfile %q reading %v packets", b.name, len(positions))
		for _, pos := range positions {
			buffer, err := b.ReadPacket(pos, &ci)
			if err != nil {
				c.finish(fmt.Errorf("error reading packets from %q @ %v: %v", b.name, pos, err))
				return
			}
			c.c <- &Packet{
				Data:        buffer,
				CaptureInfo: ci,
			}
		}
		c.finish(nil)
	}()
	return c
}

func PacketsToFile(in Packets, out io.Writer) error {
	w := pcapgo.NewWriter(out)
	w.WriteFileHeader(SnapLen, layers.LinkTypeEthernet)
	count := 0
	defer in.Close()
	for in.Next() {
		p := in.Packet()
		if err := w.WritePacket(p.CaptureInfo, p.Data); err != nil {
			// This can happen if our pipe is broken, and we don't want to blow stack
			// traces all over our users when that happens, so Error/Exit instead of
			// Fatal.
			return fmt.Errorf("error writing packet: %v", err)
		}
		count++
	}
	return in.Err()
}

type indexedPacket struct {
	*Packet
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

type Packets struct {
	mu  sync.Mutex
	p   *Packet
	c   chan *Packet
	err error
}

func (p *Packets) Packet() *Packet {
	return p.p
}
func (p *Packets) Next() bool {
	p.p = <-p.c
	return p.p != nil
}
func newPackets() Packets {
	return Packets{
		c: make(chan *Packet, 100),
	}
}
func (p *Packets) Close() {
	go func() {
		for _ = range p.c {
		}
	}()
}
func (p *Packets) finish(err error) {
	p.mu.Lock()
	p.err = err
	p.mu.Unlock()
	close(p.c)
}
func (p *Packets) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func MergePackets(in []Packets) Packets {
	out := newPackets()
	go func() {
		var h packetHeap
		for i := range in {
			defer in[i].Close()
		}
		for i, c := range in {
			if c.Next() {
				heap.Push(&h, indexedPacket{Packet: c.Packet(), i: i})
			}
			if err := c.Err(); err != nil {
				out.finish(err)
				return
			}
		}
		for h.Len() > 0 {
			p := heap.Pop(&h).(indexedPacket)
			if in[p.i].Next() {
				heap.Push(&h, indexedPacket{Packet: in[p.i].Packet(), i: p.i})
			}
			out.c <- p.Packet
			if err := in[p.i].Err(); err != nil {
				out.finish(err)
				return
			}
		}
		out.finish(nil)
	}()
	return out
}

type ThreadConfig struct {
	PacketsDirectory string
	IndexDirectory   string
}
type Config struct {
	StenotypePath string
	Threads       []ThreadConfig
	Interface     string
	Flags         []string
	Port          int
}

func (c Config) args() []string {
	return append(c.Flags,
		fmt.Sprintf("--threads=%d", len(c.Threads)),
		fmt.Sprintf("--iface=%s", c.Interface))
}
func (c Config) Directory() (_ *Directory, returnedErr error) {
	dirname, err := ioutil.TempDir("", "stenographer")
	if err != nil {
		return nil, fmt.Errorf("couldn't create temp directory: %v", err)
	}
	defer func() {
		// If this fails, remove the temp dir.
		if returnedErr != nil {
			os.RemoveAll(dirname)
		}
	}()
	for i, thread := range c.Threads {
		if thread.PacketsDirectory == "" {
			return nil, fmt.Errorf("no packet directory for thread %d", i)
		} else if err := os.Symlink(thread.PacketsDirectory, filepath.Join(dirname, strconv.Itoa(i))); err != nil {
			return nil, fmt.Errorf("couldn't create symlink for thread %d to directory %q: %v", i, thread.PacketsDirectory, err)
		}
		if thread.IndexDirectory != "" {
			if err := os.Symlink(thread.IndexDirectory, filepath.Join(dirname, strconv.Itoa(i), "INDEX")); err != nil {
				return nil, fmt.Errorf("couldn't create symlink for thread %d index to directory %q: %v", i, thread.IndexDirectory, err)
			}
		}
	}
	return newDirectory(dirname, len(c.Threads)), nil
}

func (d *Directory) Close() error {
	return os.RemoveAll(d.name)
}

func (c Config) Stenotype(d *Directory) *exec.Cmd {
	log.Printf("Starting stenotype")
	args := append(c.args(), fmt.Sprintf("--dir=%s", d.Path()))
	V(1, "Starting as %q with args %q", c.StenotypePath, args)
	return exec.Command(c.StenotypePath, args...)
}

type fileKey struct {
	basedir string
	thread  int
	name    string
}

type Directory struct {
	mu      sync.RWMutex
	name    string
	threads int
	files   map[fileKey]*BlockFile
	done    chan bool
}

func newDirectory(dirname string, threads int) *Directory {
	d := &Directory{
		name:    dirname,
		threads: threads,
		done:    make(chan bool),
		files:   map[fileKey]*BlockFile{},
	}
	go d.newFiles()
	go d.oldFiles()
	return d
}

func (d *Directory) newFiles() {
	ticker := time.NewTicker(time.Second * 15)
	defer ticker.Stop()
	for {
		select {
		case <-d.done:
			return
		case <-ticker.C:
			d.checkForNewFiles()
		}
	}
}

func (d *Directory) checkForNewFiles() {
	d.mu.Lock()
	defer d.mu.Unlock()
	gotNew := false
	for i := 0; i < d.threads; i++ {
		dirpath := filepath.Join(d.name, strconv.Itoa(i))
		files, err := ioutil.ReadDir(dirpath)
		if err != nil {
			log.Printf("could not read dir %q: %v", dirpath, err)
		}
		for _, file := range files {
			if file.IsDir() || file.Name()[0] == '.' {
				continue
			}
			key := fileKey{d.name, i, file.Name()}
			if d.files[key] != nil {
				continue
			}
			filepath := filepath.Join(dirpath, file.Name())
			bf, err := NewBlockFile(filepath)
			if err != nil {
				log.Printf("could not open blockfile %q: %v", filepath, err)
				continue
			}
			V(1, "new blockfile %q", filepath)
			d.files[key] = bf
			gotNew = true
		}
	}
	if gotNew {
		log.Printf("New blockfiles, now tracking %v", len(d.files))
	}
}

func (d *Directory) oldFiles() {
}

func (d *Directory) Path() string {
	return d.name
}

func (d *Directory) Lookup(query string) Packets {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var inputs []Packets
	for _, file := range d.files {
		inputs = append(inputs, file.Lookup(query))
	}
	return MergePackets(inputs)
}
