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

// Package config provides a method of centrally configuring the stenographer
// server.
package config

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/stenographer/base"
	"github.com/google/stenographer/blockfile"
	"github.com/google/stenographer/certs"
	"github.com/google/stenographer/indexfile"
	"github.com/google/stenographer/query"
	"golang.org/x/net/context"
)

var v = base.V // verbose logging
const (
	packetPrefix           = "PKT"
	indexPrefix            = "IDX"
	minDiskSpacePercentage = 10
	fileSyncFrequency      = 15 * time.Second

	// These files will be generated in Config.CertPath.
	clientCertFilename = "client_cert.pem"
	clientKeyFilename  = "client_key.pem"
	serverCertFilename = "server_cert.pem"
	serverKeyFilename  = "server_key.pem"
)

type ThreadConfig struct {
	PacketsDirectory   string
	IndexDirectory     string
	DiskFreePercentage int `json:",omitempty"`
}

type Config struct {
	StenotypePath string
	Threads       []ThreadConfig
	Interface     string
	Flags         []string
	Port          int
	CertPath      string // Directory where client and server certs are stored.
}

type stenotypeThread struct {
	id          int
	indexPath   string
	packetPath  string
	minDiskFree int
	files       map[string]*blockfile.BlockFile
	mu          sync.RWMutex
}

func newStenotypeThread(i int, baseDir string) *stenotypeThread {
	return &stenotypeThread{
		id:         i,
		indexPath:  filepath.Join(baseDir, indexPrefix+strconv.Itoa(i)),
		packetPath: filepath.Join(baseDir, packetPrefix+strconv.Itoa(i)),
		files:      map[string]*blockfile.BlockFile{},
	}
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

func (st *stenotypeThread) createSymlinks(config *ThreadConfig) error {
	if err := makeDirIfNecessary(config.PacketsDirectory); err != nil {
		return fmt.Errorf("thread %v could not create packet directory: %v", st.id, err)
	}
	if err := os.Symlink(config.PacketsDirectory, st.packetPath); err != nil {
		return fmt.Errorf("couldn't create symlink for thread %d to directory %q: %v",
			st.id, config.PacketsDirectory, err)
	}
	if err := makeDirIfNecessary(config.IndexDirectory); err != nil {
		return fmt.Errorf("thread %v could not create index directory: %v", st.id, err)
	}
	if err := os.Symlink(config.IndexDirectory, st.indexPath); err != nil {
		return fmt.Errorf("couldn't create symlink for index %d to directory %q: %v",
			st.id, config.IndexDirectory, err)
	}
	return nil
}

func (st *stenotypeThread) getPacketFilePath(filename string) string {
	return filepath.Join(st.packetPath, filename)
}

func (st *stenotypeThread) getIndexFilePath(filename string) string {
	return filepath.Join(st.indexPath, filename)
}

func (st *stenotypeThread) syncFilesWithDisk() {
	st.mu.Lock()
	defer st.mu.Unlock()

	newFilesCnt := 0
	for _, filename := range st.listPacketFilesOnDisk() {
		if st.files[filename] != nil {
			continue
		}
		if err := st.trackNewFile(filename); err != nil {
			log.Printf("Thread %v error tracking %q: %v", st.id, filename, err)
			continue
		}
		newFilesCnt++
	}
	if newFilesCnt > 0 {
		log.Printf("Thread %v found %d new blockfiles", st.id, newFilesCnt)
	}
}

func (st *stenotypeThread) listPacketFilesOnDisk() (out []string) {
	// Since indexes tend to be written after blockfiles, we list index files,
	// then translate them back to blockfiles.  This way, we don't get spurious
	// errors when we find blockfiles that indexes haven't been written for yet.
	files, err := ioutil.ReadDir(st.indexPath)
	if err != nil {
		log.Printf("Thread %v could not read dir %q: %v", st.id, st.indexPath, err)
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

// This method should only be called once the st.mu has been acquired!
func (st *stenotypeThread) trackNewFile(filename string) error {
	filepath := filepath.Join(st.packetPath, filename)
	bf, err := blockfile.NewBlockFile(filepath)
	if err != nil {
		return fmt.Errorf("could not open blockfile %q: %v", filepath, err)
	}
	v(1, "new blockfile %q", filepath)
	st.files[filename] = bf
	return nil
}

func (st *stenotypeThread) cleanUpOnLowDiskSpace() {
	for {
		df, err := base.PathDiskFreePercentage(st.packetPath)
		if err != nil {
			log.Printf("Thread %v could not get the free disk percentage for %q: %v", st.id, st.packetPath, err)
			return
		}
		if df > st.minDiskFree {
			v(1, "Thread %v disk space is sufficient: %v > %v", st.id, df, st.minDiskFree)
			return
		}
		log.Printf("Thread %v disk usage is high (packet path=%q): %d%% free\n", st.id, st.packetPath, df)
		if err := st.deleteOlderThreadFiles(); err != nil {
			log.Printf("Thread %v could not free up space by deleting old files: %v", st.id, err)
			return
		}
		// After deleting files, it may take a while for disk stats to be updated.
		// We add this sleep so we don't accidentally delete WAY more files than
		// we need to.
		time.Sleep(100 * time.Millisecond)
	}
}

func (st *stenotypeThread) deleteOlderThreadFiles() error {
	st.mu.Lock()
	defer st.mu.Unlock()

	oldestFile := st.getOldestFile()
	if oldestFile == "" {
		return fmt.Errorf("Thread %v no files tracked", st.id)
	}
	v(1, "Thread %v removing %q", st.id, oldestFile)
	if err := os.Remove(st.getPacketFilePath(oldestFile)); err != nil {
		return err
	}
	if err := os.Remove(st.getIndexFilePath(oldestFile)); err != nil {
		return err
	}
	return st.untrackFile(oldestFile)
}

// getOldesFile returns the oldest known file for the given thread. Packet and
// index files are named after the UNIX timestamp when they were created.
// Because they are also rotated, we know that the file with the "smallest"
// filename (as in first when lexicographically sorted) is the oldest one.
//
// This method should only be called once the st.mu has been acquired!
func (st *stenotypeThread) getOldestFile() string {
	if len(st.files) == 0 {
		return ""
	}
	var sortedFiles []string
	for name, _ := range st.files {
		sortedFiles = append(sortedFiles, name)
	}
	sort.Strings(sortedFiles)
	return sortedFiles[0]
}

// This method should only be called once the st.mu has been acquired!
func (st *stenotypeThread) untrackFile(filename string) error {
	v(1, "Thread %v untracking %q", st.id, filename)
	b := st.files[filename]
	if b == nil {
		return fmt.Errorf("trying to untrack file %q for thread %d, but that file is not monitored",
			st.getPacketFilePath(filename), st.id)
	}
	v(1, "Thread %v old blockfile %q", st.id, b.Name())
	b.Close()
	delete(st.files, filename)
	return nil
}

func (st *stenotypeThread) lookup(ctx context.Context, q query.Query) *base.PacketChan {
	st.mu.RLock()
	defer st.mu.RUnlock()
	var inputs []*base.PacketChan
	for _, file := range st.files {
		inputs = append(inputs, file.Lookup(ctx, q))
	}
	// BUG:  MergePacketChans returns asynchronously, so there's a chance
	// that we'll lose our st.mu lock while still looking up packets, then
	// close/delete files.  Figure out how to fix this.
	return base.MergePacketChans(ctx, inputs)
}

func (st *stenotypeThread) getBlockFile(name string) *blockfile.BlockFile {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.files[name]
}

// ReadConfigFile reads in the given JSON encoded configuration file and returns
// the Config object associated with the decoded configuration data.
func ReadConfigFile(filename string) (*Config, error) {
	log.Printf("Reading config %q", filename)
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("could not read config file %q: %v", filename, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var out Config
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("could not decode config file %q: %v", filename, err)
	}
	for i, thread := range out.Threads {
		if thread.DiskFreePercentage <= 0 {
			out.Threads[i].DiskFreePercentage = minDiskSpacePercentage
		}
	}
	return &out, nil
}

func (c Config) args() []string {
	return append(c.Flags,
		fmt.Sprintf("--threads=%d", len(c.Threads)),
		fmt.Sprintf("--iface=%s", c.Interface))
}

func (c Config) validateThreadsConfig() error {
	for _, thread := range c.Threads {
		if _, err := os.Stat(thread.PacketsDirectory); err != nil {
			return fmt.Errorf("invalid packets directory %q in configuration: %v", thread.PacketsDirectory, err)
		}
		if _, err := os.Stat(thread.IndexDirectory); err != nil {
			return fmt.Errorf("invalid index directory %q in configuration: %v", thread.IndexDirectory, err)
		}
	}
	return nil
}

// Serve starts up an HTTP server using http.DefaultServerMux to handle
// requests.  This server will server over TLS, using the certs
// stored in c.CertPath to verify itself to clients and verify clients.
func (c Config) Serve() error {
	clientCert, clientKey, serverCert, serverKey :=
		filepath.Join(c.CertPath, clientCertFilename),
		filepath.Join(c.CertPath, clientKeyFilename),
		filepath.Join(c.CertPath, serverCertFilename),
		filepath.Join(c.CertPath, serverKeyFilename)
	if err := certs.WriteNewCerts(clientCert, clientKey, false); err != nil {
		return fmt.Errorf("cannot write client certs: %v", err)
	}
	if err := certs.WriteNewCerts(serverCert, serverKey, true); err != nil {
		return fmt.Errorf("cannot write server certs: %v", err)
	}
	tlsConfig, err := certs.ClientVerifyingTLSConfig(clientCert)
	if err != nil {
		return fmt.Errorf("cannot verify client cert: %v", err)
	}
	server := &http.Server{
		Addr:      fmt.Sprintf("localhost:%d", c.Port),
		TLSConfig: tlsConfig,
	}
	return server.ListenAndServeTLS(serverCert, serverKey)
}

// Directory returns a new Directory for use in running Stenotype.
func (c Config) Directory() (_ *Directory, returnedErr error) {
	if err := c.validateThreadsConfig(); err != nil {
		return nil, err
	}
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
	threads := make([]*stenotypeThread, len(c.Threads))
	for i, threadConfig := range c.Threads {
		st := newStenotypeThread(i, dirname)
		st.minDiskFree = threadConfig.DiskFreePercentage
		if err := st.createSymlinks(&threadConfig); err != nil {
			return nil, err
		}
		threads[i] = st
	}
	return newDirectory(dirname, threads), nil
}

// Stenotype returns a exec.Cmd which runs the stenotype binary with all of
// the appropriate flags.
func (c Config) Stenotype(d *Directory) *exec.Cmd {
	log.Printf("Starting stenotype")
	args := append(c.args(), fmt.Sprintf("--dir=%s", d.Path()))
	v(1, "Starting as %q with args %q", c.StenotypePath, args)
	return exec.Command(c.StenotypePath, args...)
}

func (c Config) ExportDebugHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/debug/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c)
	})
}

// Directory contains information necessary to run Stenotype.
type Directory struct {
	name    string
	threads []*stenotypeThread
	done    chan bool
}

func newDirectory(dirname string, threads []*stenotypeThread) *Directory {
	d := &Directory{
		name:    dirname,
		threads: threads,
		done:    make(chan bool),
	}
	go d.callEvery(d.syncFiles, fileSyncFrequency)
	return d
}

// Close closes the directory.  This should only be done when stenotype has
// stopped using it.  After this call, Directory should no longer be used.
func (d *Directory) Close() error {
	return os.RemoveAll(d.name)
}

func (d *Directory) callEvery(cb func(), freq time.Duration) {
	ticker := time.NewTicker(freq)
	defer ticker.Stop()
	cb() // Call function immediately the first time around.
	for {
		select {
		case <-d.done:
			return
		case <-ticker.C:
			cb()
		}
	}
}

func (d *Directory) syncFiles() {
	for _, t := range d.threads {
		t.syncFilesWithDisk()
		t.cleanUpOnLowDiskSpace()
	}
}

// Path returns the underlying directory path for the given Directory.
func (d *Directory) Path() string {
	return d.name
}

// Lookup looks up the given query in all blockfiles currently known in this
// Directory.
func (d *Directory) Lookup(ctx context.Context, q query.Query) *base.PacketChan {
	var inputs []*base.PacketChan
	for _, thread := range d.threads {
		inputs = append(inputs, thread.lookup(ctx, q))
	}
	return base.MergePacketChans(ctx, inputs)
}

// ExportDebugHandlers exports a few debugging handlers to an HTTP ServeMux.
func (d *Directory) ExportDebugHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/debug/files", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		for _, thread := range d.threads {
			fmt.Fprintf(w, "Thread %d (IDX: %q, PKT: %q)\n", thread.id, thread.indexPath, thread.packetPath)
			thread.mu.RLock()
			for name := range thread.files {
				fmt.Fprintf(w, "\t%v\n", name)
			}
			thread.mu.RUnlock()
		}
	})
	mux.HandleFunc("/debug/index", func(w http.ResponseWriter, r *http.Request) {
		vals := r.URL.Query()
		threadID, err := strconv.Atoi(vals.Get("thread"))
		if threadID < 0 || threadID > len(d.threads) || err != nil {
			http.Error(w, "invalid thread", http.StatusBadRequest)
			return
		}
		thread := d.threads[threadID]
		name := vals.Get("name")
		thread.mu.RLock()
		defer thread.mu.RUnlock()
		file, ok := thread.files[name]
		if !ok {
			http.Error(w, "index not found", http.StatusNotFound)
			return
		}
		var start, finish []byte
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
	mux.HandleFunc("/debug/packets", func(w http.ResponseWriter, r *http.Request) {
		vals := r.URL.Query()
		threadID, err := strconv.Atoi(vals.Get("thread"))
		if threadID < 0 || threadID > len(d.threads) || err != nil {
			http.Error(w, "invalid thread", http.StatusBadRequest)
			return
		}
		thread := d.threads[threadID]
		name := vals.Get("name")
		thread.mu.RLock()
		defer thread.mu.RUnlock()
		file, ok := thread.files[name]
		if !ok {
			http.Error(w, "index not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		base.PacketsToFile(file.AllPackets(), w)
	})
	mux.HandleFunc("/debug/positions", func(w http.ResponseWriter, r *http.Request) {
		vals := r.URL.Query()
		threadID, err := strconv.Atoi(vals.Get("thread"))
		if threadID < 0 || threadID > len(d.threads) || err != nil {
			http.Error(w, "invalid thread", http.StatusBadRequest)
			return
		}
		thread := d.threads[threadID]
		name := vals.Get("name")
		thread.mu.RLock()
		defer thread.mu.RUnlock()
		file, ok := thread.files[name]
		if !ok {
			http.Error(w, "index not found", http.StatusNotFound)
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
