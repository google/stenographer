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
	"github.com/google/stenographer/sstable"
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

type blockFile struct {
	name string
	f    *os.File
	i    *index
}

func newBlockFile(filename string) (*blockFile, error) {
	V(1, "opening blockfile %q", filename)
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open %q: %v", filename, err)
	}
	i, err := newIndex(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open index for %q: %v", filename, err)
	}
	return &blockFile{
		f:    f,
		i:    i,
		name: filename,
	}, nil
}

// stillAtOriginalPath returns true if the file is still able to be accessed at
// its original file path.  If not, steno assumes that this file has been
// removed, and it can clean up the blockfile so it doesn't stay around on the
// filesystem as an unlinked file.
func (b *blockFile) stillAtOriginalPath() bool {
	_, err := os.Stat(b.name)
	return err == nil
}

func (b *blockFile) ReadPacket(pos int64, ci *gopacket.CaptureInfo) ([]byte, error) {
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

func (b *blockFile) Close() error {
	b.i.Close()
	return b.f.Close()
}

type int64Slice []int64

func (a int64Slice) Less(i, j int) bool {
	return a[i] < a[j]
}
func (a int64Slice) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
func (a int64Slice) Len() int {
	return len(a)
}

func (a int64Slice) Union(b int64Slice) (out int64Slice) {
	out = make(int64Slice, 0, len(a)+len(b)/2)
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

func (a int64Slice) Intersect(b int64Slice) (out int64Slice) {
	out = make(int64Slice, 0, len(a)/2)
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

type index struct {
	name string
	ss   *sstable.Table
}

func newIndex(filename string) (*index, error) {
	filename = filepath.Join(
		filepath.Dir(filename),
		"INDEX",
		filepath.Base(filename))
	V(1, "opening index %q", filename)
	ss, err := sstable.NewTable(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening index %q: %v", filename, err)
	}
	index := &index{ss: ss, name: filename}
	return index, nil
}

func (i *index) IPPositions(from, to net.IP) (int64Slice, error) {
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

func (i *index) ProtoPositions(proto byte) (int64Slice, error) {
	return i.positionsSingleKey([]byte{1, proto})
}

func (i *index) PortPositions(port uint16) (int64Slice, error) {
	var buf [3]byte
	binary.BigEndian.PutUint16(buf[1:], port)
	buf[0] = 2
	return i.positionsSingleKey(buf[:])
}

func (i *index) Dump(out io.Writer) {
	iter := i.ss.Iter([]byte{})
	for iter.Next() {
		fmt.Fprintf(out, "%v %v\n", iter.Key(), iter.Value())
	}
	if err := iter.Err(); err != nil {
		fmt.Fprintf(out, "ERR: %v", err)
	}
}

func (i *index) positionsSingleKey(key []byte) (int64Slice, error) {
	var sortedPos int64Slice
	V(4, "%q single key iterator %+v start", i.name, key)
	iter := i.ss.Iter(key)
	count := int64(0)
	for iter.Next() {
		if !bytes.Equal(key, iter.Key()) {
			V(4, "%q single key iterator high key %v", i.name, iter.Key())
			break
		}
		V(4, "%q single key iterator %v=%v", i.name, iter.Key(), iter.Value())
		pos := binary.BigEndian.Uint32(iter.Value())
		sortedPos = append(sortedPos, int64(pos))
		count++
	}
	V(4, "%q single key iterator done", i.name)
	if err := iter.Err(); err != nil {
		V(4, "%q single key iterator err=%v", i.name, err)
		return nil, err
	}
	return sortedPos, nil
}

func (i *index) positions(from, to []byte) (int64Slice, error) {
	if bytes.Equal(from, to) {
		return i.positionsSingleKey(from)
	}
	V(4, "%q multi key iterator %v:%v start", i.name, from, to)
	iter := i.ss.Iter(from)
	positions := map[uint32]bool{}
	count := int64(0)
	for iter.Next() {
		if bytes.Compare(iter.Key(), from) > 0 {
			V(4, "%q multi key iterator high key %v", i.name, iter.Key())
			break
		}
		V(4, "%q multi key iterator %v=%v", i.name, iter.Key(), iter.Value())
		pos := binary.BigEndian.Uint32(iter.Value())
		positions[pos] = true
		count++
	}
	V(4, "%q multi key iterator done", i.name)
	if err := iter.Err(); err != nil {
		V(4, "%q multi key iterator err=%v", i.name, err)
		return nil, err
	}
	sortedPos := make(int64Slice, 0, len(positions))
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

func (i *index) lookupSingleArgument(arg string) (int64Slice, error) {
	parts := strings.Split(arg, "=")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid arg: %q", arg)
	}
	var pos int64Slice
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
	V(3, "%q arg %q found %d", i.name, arg, len(pos))
	return pos, nil
}

func (i *index) lookupUnionArguments(arg string) (int64Slice, error) {
	args := strings.Split(arg, "|")
	var positions int64Slice
	c := make(chan int64Slice, len(args))
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

func (i *index) Lookup(in string) (int64Slice, error) {
	actualArgs := strings.Fields(in)
	c := make(chan int64Slice, len(actualArgs))
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
	var positions int64Slice
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

func (i *index) Close() error {
	return i.ss.Close()
}

type Packet struct {
	Data []byte
	gopacket.CaptureInfo
}

func (b *blockFile) Lookup(in string) Packets {
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

func (b *blockFile) DumpIndex(out io.Writer) {
	b.i.Dump(out)
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
		discarded := 0
		for _ = range p.c {
			discarded++
		}
		if discarded > 0 {
			V(2, "discarded %v", discarded)
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
		count := 0
		defer func() {
			V(1, "merged %d streams for %d total packets", len(in), count)
		}()
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
			count++
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
		if _, err := os.Stat(thread.PacketsDirectory); err != nil {
			return nil, fmt.Errorf("invalid packets directory %q in configuration: %v", thread.PacketsDirectory, err)
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
	files   map[fileKey]*blockFile
	done    chan bool
}

func newDirectory(dirname string, threads int) *Directory {
	d := &Directory{
		name:    dirname,
		threads: threads,
		done:    make(chan bool),
		files:   map[fileKey]*blockFile{},
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
			d.checkForRemovedFiles()
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
			bf, err := newBlockFile(filepath)
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

func (d *Directory) checkForRemovedFiles() {
	d.mu.Lock()
	defer d.mu.Unlock()
	count := 0
	for key, b := range d.files {
		if !b.stillAtOriginalPath() {
			V(1, "old blockfile %q", b.name)
			b.Close()
			delete(d.files, key)
			count++
		}
	}
	if count > 0 {
		log.Printf("Detected %d blockfiles removed", count)
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

func (d *Directory) DumpIndex(name string, out io.Writer) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, file := range d.files {
		log.Printf("%q %q", file.name, name)
		if file.name == name {
			file.DumpIndex(out)
			return
		}
	}
}
