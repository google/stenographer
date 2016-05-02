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

package base

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/google/gopacket"
	"golang.org/x/net/context"
)

var ctx = context.Background()

func testPacketData(t *testing.T) []*Packet {
	var ci = []gopacket.CaptureInfo{
		{Timestamp: time.Unix(123, 123), CaptureLength: 3, Length: 3},
		{Timestamp: time.Unix(456, 456), CaptureLength: 3, Length: 3},
		{Timestamp: time.Unix(789, 789), CaptureLength: 3, Length: 3},
	}

	out := []*Packet{&Packet{[]byte{1, 2, 3}, ci[0]},
		&Packet{[]byte{4, 5, 6}, ci[1]},
		&Packet{[]byte{7, 8, 9}, ci[2]}}
	return out
}

func comparePacketChans(t *testing.T, want, got *PacketChan) {
	for {
		p1, ok1 := <-want.Receive()
		p2, ok2 := <-got.Receive()
		if !ok1 || !ok2 {
			if ok1 != ok2 {
				t.Errorf("missing packet:\nwant:%v\ngot:%v\n", p1, p2)
			}
			break
		}
		if p1 != p2 {
			t.Errorf("wrong packet\nwant:%v\ngot:%v\n", p1, p2)
		}
	}
}

func TestConcatPacketChans(t *testing.T) {
	packets := testPacketData(t)
	inputs := make(chan *PacketChan, 2)
	one := NewPacketChan(100)
	two := NewPacketChan(100)
	one.Send(packets[0])
	two.Send(packets[1])
	one.Close(nil)
	two.Close(nil)
	inputs <- one
	inputs <- two
	close(inputs)
	got := ConcatPacketChans(ctx, inputs)
	want := NewPacketChan(3)
	want.Send(packets[0])
	want.Send(packets[1])
	want.Close(nil)
	comparePacketChans(t, want, got)
}

func TestMergePacketChans(t *testing.T) {
	packets := testPacketData(t)
	one := NewPacketChan(100)
	two := NewPacketChan(100)
	inputs := []*PacketChan{one, two}
	one.Send(packets[1])
	two.Send(packets[0])
	one.Close(nil)
	two.Close(nil)
	got := MergePacketChans(ctx, inputs)
	want := NewPacketChan(100)
	want.Send(packets[0])
	want.Send(packets[1])
	want.Close(nil)
	comparePacketChans(t, want, got)
}

func TestUnion(t *testing.T) {
	for _, test := range []struct {
		a, b, want Positions
	}{
		{
			Positions{1, 2, 3},
			Positions{2, 3, 4},
			Positions{1, 2, 3, 4},
		},
		{
			Positions{1, 2},
			Positions{3, 4},
			Positions{1, 2, 3, 4},
		},
		{
			Positions{3, 4},
			Positions{1, 2},
			Positions{1, 2, 3, 4},
		},
	} {
		got := test.a.Union(test.b)
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("nope:\n   a: %v\n   b: %v\n got: %v\nwant: %v", test.a, test.b, got, test.want)
		}
	}
}

func TestIntersect(t *testing.T) {
	for _, test := range []struct {
		a, b, want Positions
	}{
		{
			Positions{1, 2, 3, 4},
			Positions{0, 2, 4, 5},
			Positions{2, 4},
		},
		{
			Positions{1, 2, 3},
			Positions{2, 3, 4},
			Positions{2, 3},
		},
		{
			Positions{1, 2},
			Positions{3, 4},
			Positions{},
		},
		{
			Positions{3, 4},
			Positions{1, 2},
			Positions{},
		},
	} {
		got := test.a.Intersect(test.b)
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("nope:\n   a: %v\n   b: %v\n got: %v\nwant: %v", test.a, test.b, got, test.want)
		}
	}
}

func TestPacketsToFile(t *testing.T) {
	var out bytes.Buffer
	packets := testPacketData(t)
	pc := NewPacketChan(100)
	pc.Send(packets[0])
	pc.Close(nil)
	want := []byte{
		0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x7b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
		0x01, 0x02, 0x03,
	}
	PacketsToFile(pc, &out, Limit{})
	if got := out.Bytes(); !bytes.Equal(want, got) {
		t.Errorf("wrong packets:\nwant: %+v\ngot:  %+v", want, got)
	}
}

func TestContextDone(t *testing.T) {
	ctx := NewContext(0)
	if ContextDone(ctx) {
		t.Fatal("shouldn't be done yet")
	}
	ctx.Cancel()
	if !ContextDone(ctx) {
		t.Fatal("should be done now")
	}
	ctx = NewContext(time.Microsecond)
	time.Sleep(time.Millisecond)
	if !ContextDone(ctx) {
		t.Fatal("should have timed out by now")
	}
}
