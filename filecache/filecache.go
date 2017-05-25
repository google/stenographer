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

// Package filecache provides a LRU cache of open os.File objects, closing old
// files as new ones are opened.
package filecache

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/stenographer/base"
)

var v = base.V

type CachedFile struct {
	cache *Cache

	// protected by cache.mu
	at         time.Time
	prev, next *CachedFile

	mu sync.RWMutex
	// protected by mu
	filename string
	f        *os.File
}

func NewCache(maxOpened int) *Cache {
	if maxOpened < 1 {
		panic("maxOpened must be > 0")
	}
	return &Cache{maxOpened: maxOpened}
}

type Cache struct {
	mu                sync.Mutex
	first, last       *CachedFile
	opened, maxOpened int
}

func (cf *CachedFile) moveToFront() {
	cf.at = time.Now()
	if cf.cache.first == cf {
		return
	}
	// Remove from current place in list
	if cf.prev != nil {
		cf.prev.next = cf.next
	}
	if cf.next != nil {
		cf.next.prev = cf.prev
	}
	// Update last element in list, if necessary
	if cf.cache.last == nil {
		cf.cache.last = cf
	} else if cf.cache.last == cf {
		cf.cache.last = cf.prev
	}
	// Update first element in list
	if cf.cache.first != nil {
		cf.next = cf.cache.first
		cf.cache.first.prev = cf
	}
	cf.cache.first = cf
	cf.prev = nil
}

func (c *Cache) Open(filename string) *CachedFile {
	v(3, "Deferring open of %q", filename)
	return &CachedFile{cache: c, filename: filename}
}

func (cf *CachedFile) readLockedFile() error {
	cf.cache.mu.Lock()
	cf.moveToFront()
	cf.cache.mu.Unlock()
	for {
		cf.mu.RLock()
		if cf.f != nil {
			return nil
		}
		cf.mu.RUnlock()
		if err := cf.openFile(); err != nil {
			return fmt.Errorf("lazily opening: %v", err)
		}
	}
}

func (cf *CachedFile) ReadAt(p []byte, off int64) (int, error) {
	if err := cf.readLockedFile(); err != nil {
		return 0, err
	}
	defer cf.mu.RUnlock()
	return cf.f.ReadAt(p, off)
}

func (cf *CachedFile) Read(p []byte) (int, error) {
	if err := cf.readLockedFile(); err != nil {
		return 0, err
	}
	defer cf.mu.RUnlock()
	return cf.f.Read(p)
}

func (cf *CachedFile) Stat() (os.FileInfo, error) {
	if err := cf.readLockedFile(); err != nil {
		return nil, err
	}
	defer cf.mu.RUnlock()
	return cf.f.Stat()
}

func (cf *CachedFile) Write(p []byte) (int, error) {
	return 0, fmt.Errorf("cached file not writable")
}

func (cf *CachedFile) Sync() error {
	return fmt.Errorf("cached file not syncable")
}

func (cf *CachedFile) openFile() error {
	cf.cache.mu.Lock()
	defer cf.cache.mu.Unlock()
	cf.mu.Lock()
	defer cf.mu.Unlock()
	if cf.f != nil {
		return nil
	}
	v(2, "Opening %q", cf.filename)
	newF, err := os.Open(cf.filename)
	if err != nil {
		v(1, "Open of %q failed: %v", cf.filename, err)
		return err
	}
	cf.f = newF
	cf.moveToFront()
	cf.cache.opened++
	for cf.cache.opened > cf.cache.maxOpened {
		v(3, "Cached files above max, closing last")
		oldLast := cf.cache.last
		cf.cache.last = oldLast.prev
		if cf.cache.last != nil {
			cf.cache.last.next = nil
		}
		oldLast.prev = nil
		oldLast.next = nil
		oldLast.closeFile()
	}
	return nil
}

func (cf *CachedFile) Close() error {
	// Remove me from the cache, so others can't reference me
	cf.cache.mu.Lock()
	defer cf.cache.mu.Unlock()
	cf.mu.Lock()
	defer cf.mu.Unlock()
	return cf.closeFile()
}

func (cf *CachedFile) closeFile() error {
	if cf.f == nil {
		v(3, "Close of already-closed file %q ignored", cf.filename)
		return nil
	}
	v(2, "Closing %q", cf.filename)
	cf.cache.opened--
	cf.f = nil
	return cf.f.Close()
}
