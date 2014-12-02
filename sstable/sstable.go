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

// Package sstable provides read-only functionality for iterating over leveldb
// tables (sorted-string or 'ss' tables).
//
// This package is meant solely as an internal implementation for the
// stenographer projet, so it should NOT be used by any other libraries.  It may
// change in backwards-incompatible ways at any moment.
package sstable

/* SSTable format:

LevelDB uses a structured data format, built at the base level with:
  1) 4-byte little-endian int32s
  2) unsigned varints (see Go's encoding/binary)
  3) byte slices
When reading below, assume each 4-byte int is little-endian.

LevelDB tables have a disk format consisting of a series of blocks of
arbitrary size, followed by a simple 48-byte footer.
Each block can be referenced by a 'block handle', which consists of two
int64 values (varints when serialized to disk) detailing the offset and
length of the block on disk.

Each block is actually 5 bytes longer than the length specified in its block
handle, and takes the on-disk form:
  [handle.length bytes of data][1-byte format][4-byte crc32c]
The single format byte currently differentiates between a snappy-compressed
block and an uncompressed block.  The crc32c is masked, and covers the data
and format bytes.

When uncompressed, each block contians a series of key/value pairs, of the
form:

  [sharedKeyLen][unsharedKeyLen][valueLen][unsharedKeyBytes][valueBytes]

All lengths are varints.  Decoding a key based on these is done with:

  key = previousKey[:sharedKeyLen] + unsharedKeyBytes

In other words, sharedKeyLen encodes the length of the shared prefix between
the current and previous keys.  Some entries throughout the block have
sharedKeyLen set to 0 (thus unsharedKeyBytes contains the entire key).  These
are called "restarts".  The entire block's format is:

  [entries][restarts][length of restarts]

Here, 'restarts' is a list of int32s pointing to the block offsets of
each such restart, and the final length is the number of restarts
in the block, also an int32.

The footer contains two block handles, pointing respectively to the index
and metaindex, followed by a magic 64-bit number (little-endian, 8 bytes),
used to detect that this is indeed a leveldb table file.
We do not currently use the metaindex.  The index is a special
block whose keys are the first key in each block, and whose values are the
block handles to that block.

To seek for a key in a block, one does a binary search of the restart
offsets, reading the full key from the restart position
and comparing it to the target key.  After finding the appropriate restart
key, one can then do a linear scan onward.

To seek for a key in a file, one first does a seek for the highest key less
than the target within the index block, then seeks within that block for the
highest key less than the target.  At this point, the iterator is ready to
begin, and the first call to Next() will read the first key greater than or
equal to the target, then progress from there.
*/

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"sort"
	"syscall"

	"code.google.com/p/snappy-go/snappy"
)

const (
	maxBlockHandleLength = binary.MaxVarintLen64 * 2
	// footer is always 48 bytes, even though block handles are varints and
	// may take up less than maxBlockHandleLength bytes, the rest of the footer
	// between handles and magic number is zeros.
	footerLength     = maxBlockHandleLength*2 + 8
	magicNumber      = 0xdb4775248b80fb57
	blockTrailerSize = 5          // 1-byte format + 4-byte crc32c
	maskDelta        = 0xa282ead8 // used for masking crc32c
	// Format bytes are one of the following:
	noCompression     = 0
	snappyCompression = 1
)

type blockHandle struct {
	offset, length uint64
}

// blockHandleFrom returns the block handle encoded in the data, the piece
// of the data slice that's left over when the block handles have been removed,
// and any error encountered.
func blockHandleFrom(data []byte) (blockHandle, []byte, error) {
	remaining := data
	var read int
	var b blockHandle
	b.offset, read = binary.Uvarint(data)
	if read == 0 {
		return b, nil, errors.New("could not read offset")
	}
	remaining = remaining[read:]
	b.length, read = binary.Uvarint(data[read:])
	if read == 0 {
		return b, nil, errors.New("could not read length")
	}
	remaining = remaining[read:]
	return b, remaining, nil
}

type footer struct {
	metaindex, index blockHandle
}

// footerFrom decodes the footer from the provided slice, or an error if it
// cannot.
func footerFrom(data []byte) (*footer, error) {
	if len(data) != footerLength {
		return nil, fmt.Errorf("invalid footer length %v", len(data))
	}
	magic := binary.LittleEndian.Uint64(data[40:])
	if magic != magicNumber {
		return nil, fmt.Errorf("invalid magic number %x", magic)
	}
	var f footer
	var err error
	f.metaindex, data, err = blockHandleFrom(data)
	if err != nil {
		return nil, fmt.Errorf("could not read metaindex handle: %v", err)
	}
	f.index, _, err = blockHandleFrom(data)
	if err != nil {
		return nil, fmt.Errorf("could not read index handle: %v", err)
	}
	return &f, nil
}

// black magic.
func unmaskCRC(crc uint32) uint32 {
	crc -= maskDelta
	return ((crc >> 17) | (crc << 15))
}

// readBlock returns the set of bytes which comprise the block pointed to
// by the given handle.  Note that these may not correspond directly to bytes
// on disk if the block is compressed.
func readBlock(f []byte, b blockHandle) ([]byte, error) {
	actualLength := int(b.length) + blockTrailerSize
	if int(b.offset)+actualLength > len(f) {
		return nil, fmt.Errorf("could not read %d bytes at offset %d, size is %v",
			b.length, b.offset, len(f))
	}
	out := f[int(b.offset) : int(b.offset)+actualLength]
	wantCRC := unmaskCRC(binary.LittleEndian.Uint32(out[int(b.length)+1:]))
	gotCRC := crc32.Checksum(out[:int(b.length)+1], crc32.MakeTable(crc32.Castagnoli))
	if gotCRC != wantCRC {
		return nil, fmt.Errorf("crc mismatch, got %x want %x", gotCRC, wantCRC)
	}
	switch out[int(b.length)] {
	case noCompression:
		return out[:int(b.length)], nil
	case snappyCompression:
		decoded, err := snappy.Decode(nil, out[:int(b.length)])
		if err != nil {
			return nil, fmt.Errorf("unable to snappy decompress: %v", err)
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("invalid compression type %d", out[int(b.length)])
	}
}

// Table exposes a single on-disk table for querying.
type Table struct {
	name   string
	f      *os.File
	footer *footer
	index  *block
	mmap   []byte
}

// NewTable opens the named file as an on-disk sstable.
func NewTable(filename string) (*Table, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open %q: %v", filename, err)
	}
	done := false
	t := &Table{name: filename, f: f}
	defer func() {
		if !done {
			t.Close()
		}
	}()
	stat, err := t.f.Stat()
	if err != nil {
		return nil, fmt.Errorf("could not stat: %v", err)
	}
	size := stat.Size()
	if size < footerLength {
		return nil, fmt.Errorf("size too small: %v < %v", size, footerLength)
	}

	// mmap the file.
	t.mmap, err = syscall.Mmap(int(t.f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("unable to mmap file: %v", err)
	}

	if t.footer, err = footerFrom(t.mmap[size-footerLength:]); err != nil {
		return nil, fmt.Errorf("could not decode footer: %v", err)
	} else if t.index, err = t.newBlock(t.footer.index); err != nil {
		return nil, fmt.Errorf("could not read index block: %v", err)
	}
	// TODO:  we do nothing with the meta-index... should we?
	done = true
	return t, nil
}

// Close closes the underlying table.
func (t *Table) Close() error {
	if t.mmap != nil {
		if err := syscall.Munmap(t.mmap); err != nil {
			return err
		}
	}
	return t.f.Close()
}

type block struct {
	data []byte
	// restarts is the offset to the first restart, numRestarts is the total
	// number of restarts in the block.  See format discussion above.
	restarts, numRestarts int
}

// newBlock returns the block referenced by the given handle, or an error if
// unable to read it.
func (t *Table) newBlock(b blockHandle) (*block, error) {
	// TODO:  some simple block caching here would probably be great.
	data, err := readBlock(t.mmap, b)
	if err != nil {
		return nil, err
	}
	var blk block
	blk.data = data
	if len(data) < 4 {
		return nil, fmt.Errorf("block too small: %v", data)
	}
	blk.numRestarts = int(binary.LittleEndian.Uint32(data[len(data)-4:]))
	if len(data)-4 < blk.numRestarts*4 {
		return nil, fmt.Errorf("block too small (%d) for %d restarts:\n%v", len(data), blk.numRestarts, hex.Dump(data))
	}
	blk.restarts = len(data) - blk.numRestarts*4 - 4
	return &blk, nil
}

// iter creates an iterator for this block.
func (b *block) iter() *blockIterator {
	return &blockIterator{block: b}
}

// blockIterator contains all mutable information necessary to iterate over
// a single block.
type blockIterator struct {
	*block            // the block we're iterating over.
	key, value []byte // the current decoded key/value.
	offset     int    // offset of the next key/value to read.
	err        error  // any error we've encountered.
	justSeeked bool   // if true, first Next() call should do nothing.
}

func (b *blockIterator) Err() error {
	return b.err
}

func (b *blockIterator) Key() []byte {
	if b.key == nil || b.justSeeked {
		panic("call Next() before Key()")
	}
	return b.key
}
func (b *blockIterator) Value() []byte {
	if b.key == nil || b.justSeeked {
		panic("call Next() before Value()")
	}
	return b.value
}

// seekToRestart points the location of the iterator at the offset specified
// by the index element in the restart list.
func (b *blockIterator) seekToRestart(index int) {
	if index > b.numRestarts {
		b.err = fmt.Errorf("cannot seek to restart %d", index)
		return
	}
	offset := int(binary.LittleEndian.Uint32(b.data[b.restarts+index*4:]))
	b.offset = offset
	b.value = b.data[b.offset:b.offset]
}

// decodeNext decodes the bytes currently pointed to by b.offset, returning:
//  sharedKey:    number of prefix bytes common between new and current key
//  unsharedKey:  number of bytes to append to shared prefix bytes for new key
//  val:          number of bytes in new value
//  offset:       offset in block of the first byte in unsharedKey
//  err:          any error encountered decoding
func (b *blockIterator) decodeNext() (sharedKey, unsharedKey, val, offset int, err error) {
	offset = b.offset
	num, n := binary.Uvarint(b.data[offset:])
	if n == 0 {
		err = errors.New("could not get sharedKey")
		return
	}
	offset += n
	sharedKey = int(num)
	num, n = binary.Uvarint(b.data[offset:])
	if n == 0 {
		err = errors.New("could not get unsharedKey")
		return
	}
	offset += n
	unsharedKey = int(num)
	num, n = binary.Uvarint(b.data[offset:])
	if n == 0 {
		err = errors.New("could not get val")
		return
	}
	offset += n
	val = int(num)
	if sharedKey > len(b.key) {
		err = fmt.Errorf("sharedKey %v > key length %v", sharedKey, len(b.key))
	} else if unsharedKey+val+b.offset > b.restarts {
		err = errors.New("total size greater than block space allows")
	}
	return
}

// Next recomputes the key/value of the iterator by reading the block starting
// at b.offset.  It returns false when an error has occurred, or when it has
// reached the end of the block.
func (b *blockIterator) Next() bool {
	if b.offset >= b.restarts || b.err != nil {
		return false
	}
	if b.justSeeked {
		// We're already pointing at the first key/value we need to.
		b.justSeeked = false
		return true
	}
	sharedKey, unsharedKey, val, offset, err := b.decodeNext()
	if err != nil {
		b.err = err
		return false
	}
	b.offset = offset
	if sharedKey > len(b.key) {
		b.err = fmt.Errorf("shared key too long")
		return false
	}
	b.key = append(b.key[:sharedKey], b.data[b.offset:b.offset+unsharedKey]...)
	b.offset += unsharedKey
	b.value = b.data[b.offset : b.offset+val]
	b.offset += val
	return true
}

// Seek to the first key >= target.
func (b *blockIterator) Seek(target []byte) {
	// First, we do a binary search to find the first key >= target.
	n := sort.Search(b.numRestarts, func(index int) bool {
		if b.err != nil {
			return true // return something consistent to get out of the search
		}
		b.seekToRestart(index)
		sharedKey, unsharedKey, _, offset, err := b.decodeNext()
		if err != nil {
			b.err = err
			return true
		} else if sharedKey != 0 {
			b.err = errors.New("shared key != 0 at restart index")
			return true
		}
		key := b.data[offset : offset+unsharedKey]
		return bytes.Compare(key, target) >= 0
	})
	if b.err != nil {
		return
	}
	// If we get here, n is the index of the first restart with key >= target.
	// We want the last restart with key < target, so decrement.
	if n > 0 {
		n--
	}
	b.seekToRestart(n)

	// Seek past the restart until we get to the first key >= target.
	for b.err == nil {
		if !b.Next() {
			return
		}
		if bytes.Compare(b.Key(), target) >= 0 {
			// we mark justSeeked, so that the first call to next doesn't advance but
			// instead returns the value we've just found, IE: the first key >=
			// target.
			b.justSeeked = true
			return
		}
	}
}

// twoLevelIterator handles seeking in the index block, then using that to find
// the first data block and iterate from there.
type twoLevelIterator struct {
	tbl   *Table
	index *blockIterator
	data  *blockIterator
	err   error
}

func (t *twoLevelIterator) Err() error {
	return t.err
}

// nextDataBlock reads the block handle for the next block from our index
// iterator, then sets up our data iterator to point at it.
func (t *twoLevelIterator) nextDataBlock() bool {
	if !t.index.Next() {
		t.index = nil
		return false
	}
	handle, _, err := blockHandleFrom(t.index.Value())
	if err != nil {
		t.err = err
		return false
	}
	dataBlock, err := t.tbl.newBlock(handle)
	if err != nil {
		t.err = err
		return false
	}
	t.data = dataBlock.iter()
	return true
}

func (t *twoLevelIterator) Seek(target []byte) {
	t.index.Seek(target)
	if t.nextDataBlock() {
		t.data.Seek(target)
	}
}

func (t *twoLevelIterator) Next() bool {
	if t.err != nil || t.index == nil {
		return false
	}
	for {
		if t.data.Next() {
			return true
		}
		if err := t.data.Err(); err != nil {
			t.err = err
			return false
		}
		if !t.nextDataBlock() {
			return false
		}
	}
}

func (t *twoLevelIterator) Key() []byte {
	return t.data.Key()
}

func (t *twoLevelIterator) Value() []byte {
	return t.data.Value()
}

// Iter provides a simple iteration interface over a table.  Each iterator is
// not safe for concurrent access, but any number of iterators on the same
// file may be used concurrently.
//
// Usage:
//   iter := tbl.Iter(startKey)
//   for iter.Next() {
//     fmt.Println(iter.Key(), iter.Value())
//   }
//   if err := iter.Err(); err != nil {
//     fmt.Println("ERR:", err)
//   }
type Iter interface {
	// Next advances the iterator.
	Next() bool
	// Key provides the current key of the iterator.  This slice is invalidated by
	// each Next call.
	Key() []byte
	// Value provides the current value of the iterator.  This slice is invalidated by
	// each Next call.
	Value() []byte
	// Err returns any error the iterator has encountered.  If Err would return a
	// non-nil error, then Next() will also return false.
	Err() error
}

// Iter creates a new iterator over the table, starting at the given key.
// Iter is safe to call concurrently.
func (t *Table) Iter(start []byte) Iter {
	iter := &twoLevelIterator{
		tbl:   t,
		index: t.index.iter(),
	}
	iter.Seek(start)
	return iter
}
