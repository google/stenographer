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

// Package thread contains code for interacting with a single stenotype thread.
package thread

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/stenographer/base"
	"github.com/google/stenographer/blockfile"
	"github.com/google/stenographer/config"
	"github.com/google/stenographer/filecache"
	"github.com/google/stenographer/httputil"
	"github.com/google/stenographer/indexfile"
	"github.com/google/stenographer/query"
	"github.com/google/stenographer/stats"
	"golang.org/x/net/context"
)

var (
	v            = base.V // verbose logging
	currentFiles = stats.S.Get("current_files")
	agedFiles    = stats.S.Get("aged_files")
)

const (
	packetPrefix = "PKT"
	indexPrefix  = "IDX"
)

// Thread watches the environment of a single stenotype thread.
// Stenotype runs multiple threads, each of which interacts with a specific set
// of directories in the environment.  Each stenotype thread has a corresponding
// Thread object server-side which watches for file changes, cleans up old/dead
// files, etc.
type Thread struct {
	id              int
	conf            config.ThreadConfig
	indexPath       string
	packetPath      string
	files           map[string]*blockfile.BlockFile
	mu              sync.RWMutex
	fileLastSeen    time.Time
	fc              *filecache.Cache
	newFileThrottle chan bool
}

// Threads creates a set of thread objects based on a set of ThreadConfigs.
func Threads(configs []config.ThreadConfig, baseDir string, fc *filecache.Cache) ([]*Thread, error) {
	threads := make([]*Thread, len(configs))
	for i, conf := range configs {
		thread := &Thread{
			id:              i,
			conf:            conf,
			indexPath:       filepath.Join(baseDir, indexPrefix+strconv.Itoa(i)),
			packetPath:      filepath.Join(baseDir, packetPrefix+strconv.Itoa(i)),
			files:           map[string]*blockfile.BlockFile{},
			fileLastSeen:    time.Now(),
			fc:              fc,
			newFileThrottle: make(chan bool, 32),
		}
		if err := thread.createSymlinks(); err != nil {
			return nil, err
		}
		threads[i] = thread
	}
	return threads, nil
}

func makeDirIfNecessary(dir string) error {
	if stat, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("could not create directory %q: %v", dir, err)
		}
	} else if err != nil {
		return fmt.Errorf("could not stat directory %q: %v", dir, err)
	} else if !stat.IsDir() {
		return fmt.Errorf("%q is not a directory", dir)
	}
	return nil
}

func (t *Thread) createSymlinks() error {
	if err := makeDirIfNecessary(t.conf.PacketsDirectory); err != nil {
		return fmt.Errorf("thread %v could not create packet directory: %v", t.id, err)
	}
	if err := os.Symlink(t.conf.PacketsDirectory, t.packetPath); err != nil {
		return fmt.Errorf("couldn't create symlink for thread %d to directory %q: %v",
			t.id, t.conf.PacketsDirectory, err)
	}
	if err := makeDirIfNecessary(t.conf.IndexDirectory); err != nil {
		return fmt.Errorf("thread %v could not create index directory: %v", t.id, err)
	}
	if err := os.Symlink(t.conf.IndexDirectory, t.indexPath); err != nil {
		return fmt.Errorf("couldn't create symlink for index %d to directory %q: %v",
			t.id, t.conf.IndexDirectory, err)
	}
	return nil
}

func (t *Thread) getPacketFilePath(filename string) string {
	return filepath.Join(t.packetPath, filename)
}

func (t *Thread) getIndexFilePath(filename string) string {
	return filepath.Join(t.indexPath, filename)
}

func (t *Thread) syncFilesWithDisk() {
	fido := base.Watchdog(time.Minute*5, "syncing files with disk") // 5 min for initial list of files
	defer fido.Stop()
	newFilesCnt := int64(0)
	var wg sync.WaitGroup
	for _, filename := range t.listPacketFilesOnDisk() {
		filename := filename
		wg.Add(1)
		go func() {
			t.newFileThrottle <- true
			defer func() {
				<-t.newFileThrottle
				wg.Done()
			}()
			t.mu.Lock()
			current := t.files[filename]
			t.mu.Unlock()
			if current != nil {
				return
			}
			if err := t.trackNewFile(filename); err != nil {
				log.Printf("Thread %v error tracking %q: %v", t.id, filename, err)
				return
			}
			atomic.AddInt64(&newFilesCnt, 1)
		}()
	}
	wg.Wait()
	if newFilesCnt > 0 {
		v(0, "Thread %v found %d new blockfiles", t.id, newFilesCnt)
	}
}

func (t *Thread) listPacketFilesOnDisk() (out []string) {
	// Since indexes tend to be written after blockfiles, we list index files,
	// then translate them back to blockfiles.  This way, we don't get spurious
	// errors when we find blockfiles that indexes haven't been written for yet.
	files, err := ioutil.ReadDir(t.indexPath)
	if err != nil {
		log.Printf("Thread %v could not read dir %q: %v", t.id, t.indexPath, err)
		return nil
	}
	for _, file := range files {
		if file.IsDir() || file.Name()[0] == '.' {
			continue
		}
		out = append(out, indexfile.BlockfilePathFromIndexPath(file.Name()))
	}
	return
}

// This method should only be called once the t.mu has been acquired!
func (t *Thread) trackNewFile(filename string) error {
	filepath := filepath.Join(t.packetPath, filename)
	bf, err := blockfile.NewBlockFile(filepath, t.fc)
	if err != nil {
		return fmt.Errorf("could not open blockfile %q: %v", filepath, err)
	}
	v(1, "new blockfile %q", filepath)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.files[filename] = bf
	currentFiles.Increment()
	t.fileLastSeen = time.Now()
	return nil
}

func (t *Thread) cleanUpOnLowDiskSpace() {
	if len(t.files) == 0 {
		return // cannot clean up files if we don't have any.
	}
	fido := base.Watchdog(time.Minute, "cleaning up low disk space")
	defer fido.Stop()
	for {
		fido.Reset(time.Minute)
		if len(t.files) > t.conf.MaxDirectoryFiles {
			v(1, "Thread %v too many files. %d > %d, deleting", t.id, len(t.files), t.conf.MaxDirectoryFiles)
			t.deleteOldestThreadFiles(len(t.files) - t.conf.MaxDirectoryFiles)
			continue
		}
		df, err := base.PathDiskFreePercentage(t.packetPath)
		if err != nil {
			log.Printf("Thread %v could not get the free disk percentage for %q: %v", t.id, t.packetPath, err)
			return
		}
		if df > t.conf.DiskFreePercentage {
			v(1, "Thread %v disk space is sufficient: %v > %v", t.id, df, t.conf.DiskFreePercentage)
			return
		}
		v(0, "Thread %v disk usage is high (packet path=%q): %d%% < %d%% free\n", t.id, t.packetPath, df, t.conf.DiskFreePercentage)
		t.deleteOldestThreadFiles(1)
		// After deleting files, it may take a while for disk stats to be updated.
		// We add this sleep so we don't accidentally delete WAY more files than
		// we need to.
		time.Sleep(100 * time.Millisecond)
	}
}

func tryToDeleteFile(filename string) {
	v(2, "Deleting %q", filename)
	if err := os.Remove(filename); err != nil {
		log.Printf("Unable to delete file %q: %v", filename, err)
	}
}

// deleteOldestThreadFile deletes the single oldest file held by this thread.
// It should only be called if the thread has at least one file (should be
// checked by the caller beforehand).
func (t *Thread) deleteOldestThreadFiles(n int) {
	files := t.getSortedFiles()
	for i := 0; i < n && i < len(files); i++ {
		toDelete := files[i]
		v(1, "Thread %v removing %q", t.id, toDelete)
		go tryToDeleteFile(t.getPacketFilePath(toDelete))
		go tryToDeleteFile(t.getIndexFilePath(toDelete))
	}
	for i := 0; i < n && i < len(files); i++ {
		toDelete := files[i]
		if err := t.untrackFile(toDelete); err != nil {
			log.Fatalf("Failure to untrack file: %v", err)
		}
	}
}

// getSortedFiles returns files frm the thread in the order they were created,
// and thus in the order their packets should appear.
//
// This method should only be called once the t.mu has been acquired!
func (t *Thread) getSortedFiles() []string {
	var sortedFiles []string
	for name := range t.files {
		sortedFiles = append(sortedFiles, name)
	}
	sort.Strings(sortedFiles)
	return sortedFiles
}

// This method should only be called once the t.mu has been acquired!
func (t *Thread) untrackFile(filename string) error {
	v(1, "Thread %v untracking %q", t.id, filename)
	b := t.files[filename]
	if b == nil {
		return fmt.Errorf("trying to untrack file %q for thread %d, but that file is not monitored",
			t.getPacketFilePath(filename), t.id)
	}
	v(1, "Thread %v old blockfile %q", t.id, b.Name())
	b.Close()
	delete(t.files, filename)
	agedFiles.Increment()
	currentFiles.IncrementBy(-1)
	return nil
}

// FileLastSeen returns the last timne this thread saw a new file from
// stenotype.
func (t *Thread) FileLastSeen() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.fileLastSeen
}

const concurrentBlockfileReadsPerThread = 10

// Lookup looks up packets that match a given query within the files owned by a
// single stenotype thread.
func (t *Thread) Lookup(ctx context.Context, q query.Query) *base.PacketChan {
	t.mu.RLock()
	inputs := make(chan *base.PacketChan, concurrentBlockfileReadsPerThread)
	out := base.ConcatPacketChans(ctx, inputs)
	var files []*blockfile.BlockFile
	for _, file := range t.getSortedFiles() {
		files = append(files, t.files[file])
	}
	t.mu.RUnlock()
	go func() {
		defer func() {
			close(inputs)
			<-out.Done()
		}()
		for _, file := range files {
			packets := base.NewPacketChan(100)
			select {
			case inputs <- packets:
				go file.Lookup(ctx, q, packets)
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// SyncFiles checks the disk to see if stenotype has created any new files, or
// if old files should be deleted.
func (t *Thread) SyncFiles() {
	t.syncFilesWithDisk()
	t.mu.Lock()
	t.cleanUpOnLowDiskSpace()
	t.mu.Unlock()
}

// ExportDebugHandlers exports a set of HTTP handlers on /debug/t<thread id> for
// querying internal state from this thread.
func (t *Thread) ExportDebugHandlers(mux *http.ServeMux) {
	prefix := fmt.Sprintf("/debug/t%d", t.id)
	mux.HandleFunc(prefix+"/files", func(w http.ResponseWriter, r *http.Request) {
		w = httputil.Log(w, r, false)
		defer log.Print(w)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Thread %d (IDX: %q, PKT: %q)\n", t.id, t.indexPath, t.packetPath)
		t.mu.RLock()
		for name := range t.files {
			fmt.Fprintf(w, "\t%v\n", name)
		}
		t.mu.RUnlock()
	})
	mux.HandleFunc(prefix+"/index", func(w http.ResponseWriter, r *http.Request) {
		w = httputil.Log(w, r, false)
		defer log.Print(w)
		t.mu.RLock()
		defer t.mu.RUnlock()
		vals := r.URL.Query()
		file := t.files[vals.Get("name")]
		if file == nil {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		var start, finish []byte
		var err error
		if s := vals.Get("start"); s != "" {
			start, err = hex.DecodeString(s)
			if err != nil {
				http.Error(w, "bad start", http.StatusBadRequest)
				return
			}
		}
		if f := vals.Get("finish"); f != "" {
			finish, err = hex.DecodeString(f)
			if err != nil {
				http.Error(w, "bad finish", http.StatusBadRequest)
				return
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		file.DumpIndex(w, start, finish)
	})
	mux.HandleFunc(prefix+"/packets", func(w http.ResponseWriter, r *http.Request) {
		w = httputil.Log(w, r, false)
		defer log.Print(w)
		limit, err := base.LimitFromHeaders(r.Header)
		if err != nil {
			http.Error(w, "Bad limit headers", http.StatusBadRequest)
			return
		}
		t.mu.RLock()
		defer t.mu.RUnlock()
		vals := r.URL.Query()
		file := t.files[vals.Get("name")]
		if file == nil {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		base.PacketsToFile(file.AllPackets(), w, limit)
	})
	mux.HandleFunc(prefix+"/positions", func(w http.ResponseWriter, r *http.Request) {
		w = httputil.Log(w, r, true)
		defer log.Print(w)
		t.mu.RLock()
		defer t.mu.RUnlock()
		vals := r.URL.Query()
		file := t.files[vals.Get("name")]
		if file == nil {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		queryBytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "could not read request body", http.StatusBadRequest)
			return
		}
		queryStr := string(queryBytes)
		q, err := query.NewQuery(queryStr)
		if err != nil {
			http.Error(w, "could not parse query", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		positions, err := file.Positions(context.Background(), q)
		if err != nil {
			fmt.Fprintf(w, "ERROR: %v", err)
			return
		}
		fmt.Fprintf(w, "POSITIONS:\n")
		if positions.IsAllPositions() {
			fmt.Fprintf(w, "\tALL")
		} else {
			var buf [4]byte
			for _, pos := range positions {
				binary.BigEndian.PutUint32(buf[:], uint32(pos))
				fmt.Fprintf(w, "\t%v\n", hex.EncodeToString(buf[:]))
			}
		}
	})
}
