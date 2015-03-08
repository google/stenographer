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

// Package base provides common utilities for other stenographer libraries.
package base

import (
	"container/heap"
	"flag"
	"fmt"
	"io"
	"log"
	"sort"
	"sync"
	"syscall"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcapgo"
	"golang.org/x/net/context"
)

var VerboseLogging = flag.Int("v", -1, "log many verbose logs")

// V provides verbose logging which can be turned on/off with the -v flag.
func V(level int, fmt string, args ...interface{}) {
	if *VerboseLogging >= level {
		log.Printf(fmt, args...)
	}
}

// Packet is a single packet with its metadata.
type Packet struct {
	Data                 []byte // The actual bytes that make up the packet
	gopacket.CaptureInfo        // Metadata about when/how the packet was captured
}

// PacketChan provides an async method for passing multiple ordered packets
// between goroutines.
type PacketChan struct {
	mu sync.Mutex
	c  chan *Packet
	// C can be used to send packets on this channel in a select.  Do NOT
	// call 'close' on it... instead call the Close function.
	C    chan<- *Packet
	err  error
	done chan struct{}
}

// Receive provides the channel from which to read packets.  It always
// returns the same channel.
func (p *PacketChan) Receive() <-chan *Packet { return p.c }

// Send sends a single packet on the channel to the receiver.
func (p *PacketChan) Send(pkt *Packet) { p.c <- pkt }

// Close closes the sending channel and sets the PacketChan's error based
// in its input.
func (p *PacketChan) Close(err error) {
	p.mu.Lock()
	p.err = err
	p.mu.Unlock()
	close(p.c)
	close(p.done)
}

// Done returns a channel that is closed when this packet channel is complete.
func (p *PacketChan) Done() <-chan struct{} {
	return p.done
}

// NewPacketChan returns a new PacketChan channel for passing packets around.
func NewPacketChan(buffer int) *PacketChan {
	pc := &PacketChan{
		c:    make(chan *Packet, buffer),
		done: make(chan struct{}),
	}
	pc.C = pc.c
	return pc
}

// Discard discards all remaining packets on the receiving end.  If you stop
// using the channel before reading all packets, you must call this function.
// It's a good idea to defer this regardless.
func (p *PacketChan) Discard() {
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

// Err gets the current error for the channel, if any exists.  This may be
// called during Next(), but if an error occurs it may only be set after Next()
// returns false the first time.
func (p *PacketChan) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// indexedPacket is used internally by MergePacketChans.
type indexedPacket struct {
	*Packet
	i int
}

// packetHeap is used internally by MergePacketChans.
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

// ConcatPacketChans concatenates packet chans in order.
func ConcatPacketChans(ctx context.Context, in <-chan *PacketChan) *PacketChan {
	out := NewPacketChan(100)
	go func() {
		for c := range in {
			c := c
			defer c.Discard()
		L:
			for c.Err() == nil {
				select {
				case pkt := <-c.Receive():
					if pkt == nil {
						break L
					}
					out.Send(pkt)
				case <-ctx.Done():
					out.Close(ctx.Err())
					return
				}
			}
			if err := c.Err(); err != nil {
				out.Close(err)
				return
			}
		}
		out.Close(nil)
	}()
	return out
}

// MergePacketChans merges an incoming set of packet chans, each sorted by
// time, returning a new single packet chan that's also sorted by time.
func MergePacketChans(ctx context.Context, in []*PacketChan) *PacketChan {
	out := NewPacketChan(100)
	go func() {
		count := 0
		defer func() {
			V(1, "merged %d streams for %d total packets", len(in), count)
		}()
		var h packetHeap
		for i := range in {
			defer in[i].Discard()
		}
		for i, c := range in {
			select {
			case pkt := <-c.Receive():
				if pkt != nil {
					heap.Push(&h, indexedPacket{Packet: pkt, i: i})
				}
				if err := c.Err(); err != nil {
					out.Close(err)
					return
				}
			case <-ctx.Done():
				out.Close(ctx.Err())
				return
			}
		}
		for h.Len() > 0 && !ContextDone(ctx) {
			p := heap.Pop(&h).(indexedPacket)
			count++
			if pkt := <-in[p.i].Receive(); pkt != nil {
				heap.Push(&h, indexedPacket{Packet: pkt, i: p.i})
			}
			out.c <- p.Packet
			if err := in[p.i].Err(); err != nil {
				out.Close(err)
				return
			}
		}
		out.Close(ctx.Err())
	}()
	return out
}

// Positions detail the offsets of packets within a blockfile.
type Positions []int64

var (
	AllPositions = Positions{-1}
	NoPositions  = Positions{}
)

func (p Positions) IsAllPositions() bool {
	return len(p) == 1 && p[0] == -1
}

func (a Positions) Less(i, j int) bool {
	return a[i] < a[j]
}
func (a Positions) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
func (a Positions) Len() int {
	return len(a)
}
func (a Positions) Sort() {
	sort.Sort(a)
}

// Union returns the union of a and b.  a and b must be sorted in advance.
// Returned slice will be sorted.
// a or b may be returned by Union, but neither a nor b will be modified.
func (a Positions) Union(b Positions) (out Positions) {
	switch {
	case a.IsAllPositions():
		return a
	case b.IsAllPositions():
		return b
	case len(a) == 0:
		return b
	case len(b) == 0:
		return a
	}
	out = make(Positions, 0, len(a)+len(b)/2)
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

// Intersect returns the intersection of a and b.  a and b must be sorted in
// advance.  Returned slice will be sorted.
// a or b may be returned by Intersect, but neither a nor b will be modified.
func (a Positions) Intersect(b Positions) (out Positions) {
	switch {
	case a.IsAllPositions():
		return b
	case b.IsAllPositions():
		return a
	case len(a) == 0:
		return a
	case len(b) == 0:
		return b
	}
	out = make(Positions, 0, len(a)/2)
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

func PathDiskFreePercentage(path string) (int, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return int(100 * stat.Bavail / stat.Blocks), nil
}

// snapLen is the max packet size we'll return in pcap files to users.
const snapLen = 65536

// PacketsToFile writes all packets from 'in' to 'out', writing out all packets
// in a valid PCAP file format.
func PacketsToFile(in *PacketChan, out io.Writer) error {
	w := pcapgo.NewWriter(out)
	w.WriteFileHeader(snapLen, layers.LinkTypeEthernet)
	count := 0
	defer in.Discard()
	for p := range in.Receive() {
		if len(p.Data) > snapLen {
			p.Data = p.Data[:snapLen]
		}
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

// ContextDone returns true if a context is complete.
func ContextDone(ctx context.Context) bool {
	// There's two ways we could do this:  by checking ctx.Done or by
	// seeing if ctx.Err != nil.  The latter, though, uses a single
	// exclusive mutex, so when the context is shared by a ton of
	// goroutines, it can actually block things quite a bit.  Checking
	// ctx.Done is much more scalable across multiple goroutines.
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
