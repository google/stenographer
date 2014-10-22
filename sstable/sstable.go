package sstable

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"sort"

	"code.google.com/p/snappy-go/snappy"
)

const (
	maxBlockHandleLength = 20
	footerLength         = maxBlockHandleLength*2 + 8
	magicNumber          = 0xdb4775248b80fb57
	blockTrailerSize     = 5
	maskDelta            = 0xa282ead8
	noCompression        = 0
	snappyCompression    = 1
)

type blockHandle struct {
	offset, length uint64
}

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

func unmaskCRC(crc uint32) uint32 {
	crc -= maskDelta
	return ((crc >> 17) | (crc << 15))
}

func readBlock(f io.ReaderAt, b blockHandle) ([]byte, error) {
	actualLength := int64(b.length) + blockTrailerSize
	out := make([]byte, actualLength)
	n, err := f.ReadAt(out, int64(b.offset))
	if int64(n) != actualLength {
		return nil, fmt.Errorf("could not read %d bytes at offset %d, read %d: %v",
			int64(b.length), b.offset, n, err)
	}
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

type Table struct {
	name   string
	f      *os.File
	footer *footer
	index  *block
}

func NewTable(filename string) (*Table, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open %q: %v", filename, err)
	}
	t := &Table{name: filename, f: f}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("could not stat: %v", err)
	}
	size := stat.Size()
	var footerBytes [footerLength]byte
	if n, err := f.ReadAt(footerBytes[:], size-footerLength); n != footerLength {
		return nil, fmt.Errorf("could not read footer bytes: %v", err)
	} else if t.footer, err = footerFrom(footerBytes[:]); err != nil {
		return nil, fmt.Errorf("could not decode footer: %v", err)
	}

	indexBlock, err := t.newBlock(t.footer.index)
	if err != nil {
		return nil, fmt.Errorf("could not read index block: %v", err)
	}
	t.index = indexBlock
	/*
	  metaBlock, err := readBlock(f, t.footer.metaindex)
	  if err != nil {
	    return nil, fmt.Errorf("could not read metaindex block: %v", err)
	  }
	*/
	f = nil
	return t, nil
}

func (t *Table) Close() error {
	return t.f.Close()
}

type block struct {
	data                  []byte
	restarts, numRestarts int
}

func (t *Table) newBlock(b blockHandle) (*block, error) {
	data, err := readBlock(t.f, b)
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

func (b *block) iter() *blockIterator {
	return &blockIterator{block: b}
}

type blockIterator struct {
	*block
	key, value []byte
	current    int
	err        error
}

func (b *blockIterator) Err() error {
	return b.err
}

func (b *blockIterator) Key() []byte {
	return b.key
}
func (b *blockIterator) Value() []byte {
	return b.value
}

func (b *block) restartPoint(index int) int {
	if index > b.numRestarts {
		panic("invalid restart")
	}
	return int(binary.LittleEndian.Uint32(b.data[b.restarts+index*4:]))
}

func (b *blockIterator) seekToRestart(index int) {
	offset := b.restartPoint(index)
	b.current = offset
	b.value = b.data[b.current:b.current]
}

func (b *blockIterator) decodeNext() (sharedKey, unsharedKey, val, offset int, err error) {
	offset = b.current
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
	} else if unsharedKey+val+b.current > b.restarts {
		err = errors.New("total size greater than block space allows")
	}
	return
}

type Iter interface {
	Next() bool
	Key() []byte
	Value() []byte
	Err() error
}

func (b *blockIterator) Next() bool {
	if b.current >= b.restarts {
		return false
	}
	sharedKey, unsharedKey, val, offset, err := b.decodeNext()
	if err != nil {
		b.err = err
		return b.nope()
	}
	b.current = offset
	if sharedKey > len(b.key) {
		b.err = fmt.Errorf("shared key too long")
		return false
	}
	b.key = append(b.key[:sharedKey], b.data[b.current:b.current+unsharedKey]...)
	b.current += unsharedKey
	b.value = b.data[b.current : b.current+val]
	b.current += val
	return true
}

func (b *blockIterator) nope() bool {
	b.current = b.restarts
	return false
}

// Seek to the first key >= target.
func (b *blockIterator) Seek(target []byte) {
	n := sort.Search(b.numRestarts, func(index int) bool {
		b.seekToRestart(index)
		sharedKey, unsharedKey, _, offset, err := b.decodeNext()
		if err != nil {
			b.err = err
		}
		if b.err != nil || sharedKey != 0 {
			return true
		}
		key := b.data[offset : offset+unsharedKey]
		return bytes.Compare(key, target) >= 0
	})
	if b.err != nil {
		b.nope()
		return
	}
	if n > 0 {
		n--
	}
	b.seekToRestart(n)
	for b.err == nil {
		last := *b
		last.key = append([]byte(nil), last.key...)
		if !b.Next() {
			return
		}
		if bytes.Compare(b.Key(), target) >= 0 {
			*b = last
			return
		}
	}
}

type twoLevelIterator struct {
	tbl   *Table
	index *blockIterator
	data  *blockIterator
	err   error
}

func (t *twoLevelIterator) Err() error {
	return t.err
}

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
	t.nextDataBlock()
	t.data.Seek(target)
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

func (t *Table) Iter(start []byte) Iter {
	iter := &twoLevelIterator{
		tbl:   t,
		index: t.index.iter(),
	}
	iter.Seek(start)
	return iter
}
