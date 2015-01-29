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
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/stenographer/base"
	"github.com/google/stenographer/blockfile"
	"github.com/google/stenographer/certs"
	"github.com/google/stenographer/httplog"
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

// ThreadConfig is a json-decoded configuration for each stenotype thread,
// detailing where it should store data and how much disk space it should keep
// available on each disk.
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
	id           int
	indexPath    string
	packetPath   string
	minDiskFree  int
	files        map[string]*blockfile.BlockFile
	mu           sync.RWMutex
	fileLastSeen time.Time
}

func newStenotypeThread(i int, baseDir string) *stenotypeThread {
	return &stenotypeThread{
		id:           i,
		indexPath:    filepath.Join(baseDir, indexPrefix+strconv.Itoa(i)),
		packetPath:   filepath.Join(baseDir, packetPrefix+strconv.Itoa(i)),
		files:        map[string]*blockfile.BlockFile{},
		fileLastSeen: time.Now(),
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
		st.fileLastSeen = time.Now()
	}
	if newFilesCnt > 0 {
		v(0, "Thread %v found %d new blockfiles", st.id, newFilesCnt)
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
		v(0, "Thread %v disk usage is high (packet path=%q): %d%% free\n", st.id, st.packetPath, df)
		if len(st.files) == 0 {
			log.Printf("Thread %v could not free up space:  no files available", st.id)
		} else if err := st.deleteOldestThreadFile(); err != nil {
			log.Printf("Thread %v could not free up space by deleting old files: %v", st.id, err)
			return
		}
		// After deleting files, it may take a while for disk stats to be updated.
		// We add this sleep so we don't accidentally delete WAY more files than
		// we need to.
		time.Sleep(100 * time.Millisecond)
	}
}

// deleteOldestThreadFile deletes the single oldest file held by this thread.
// It should only be called if the thread has at least one file (should be
// checked by the caller beforehand).
func (st *stenotypeThread) deleteOldestThreadFile() error {
	oldestFile := st.getSortedFiles()[0]
	v(1, "Thread %v removing %q", st.id, oldestFile)
	if err := os.Remove(st.getPacketFilePath(oldestFile)); err != nil {
		return err
	}
	if err := os.Remove(st.getIndexFilePath(oldestFile)); err != nil {
		return err
	}
	return st.untrackFile(oldestFile)
}

// getSortedFiles returns files frm the thread in the order they were created,
// and thus in the order their packets should appear.
//
// This method should only be called once the st.mu has been acquired!
func (st *stenotypeThread) getSortedFiles() []string {
	var sortedFiles []string
	for name, _ := range st.files {
		sortedFiles = append(sortedFiles, name)
	}
	sort.Strings(sortedFiles)
	return sortedFiles
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

func (s *stenotypeThread) FileLastSeen() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fileLastSeen
}

const concurrentBlockfileReadsPerThread = 10

func (st *stenotypeThread) lookup(ctx context.Context, q query.Query) *base.PacketChan {
	st.mu.RLock()
	inputs := make(chan *base.PacketChan, concurrentBlockfileReadsPerThread)
	out := base.ConcatPacketChans(ctx, inputs)
	go func() {
		defer func() {
			close(inputs)
			<-out.Done()
			st.mu.RUnlock()
		}()
		for _, file := range st.getSortedFiles() {
			packets := base.NewPacketChan(100)
			select {
			case inputs <- packets:
				go st.files[file].Lookup(ctx, q, packets)
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// ReadConfigFile reads in the given JSON encoded configuration file and returns
// the Config object associated with the decoded configuration data.
func ReadConfigFile(filename string) (*Config, error) {
	v(0, "Reading config %q", filename)
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
	d := &Directory{
		conf:    c,
		name:    dirname,
		threads: threads,
		done:    make(chan bool),
	}
	go d.callEvery(d.syncFiles, fileSyncFrequency)
	return d, nil
}

// Stenotype returns a exec.Cmd which runs the stenotype binary with all of
// the appropriate flags.
func (d *Directory) Stenotype() *exec.Cmd {
	v(0, "Starting stenotype")
	args := append(d.conf.args(), fmt.Sprintf("--dir=%s", d.Path()))
	v(1, "Starting as %q with args %q", d.conf.StenotypePath, args)
	return exec.Command(d.conf.StenotypePath, args...)
}

func (c Config) ExportDebugHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/debug/config", func(w http.ResponseWriter, r *http.Request) {
		w = httplog.New(w, r, false)
		defer log.Print(w)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c)
	})
}

// Directory contains information necessary to run Stenotype.
type Directory struct {
	conf    Config
	name    string
	threads []*stenotypeThread
	done    chan bool
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

func (d *Directory) removeHiddenFiles(dirs []string) {
	log.Printf("Checking %v for stale pkt/idx files...", d.name)
	for _, dir := range dirs {
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			v(1, "Hidden file cleanup failed, could not read directory: %v", err)
			continue
		}
		for _, file := range files {
			if !file.IsDir() {
				if strings.HasPrefix(file.Name(), ".") {
					if err := os.Remove(dir + "/" + file.Name()); err != nil {
						v(1, "Unable to remove hidden file: %v", err)
					}
					log.Printf("Deleted stale output file: %v", file.Name())
				}
			}
		}
	}
}

func (d *Directory) syncFiles() {
	for _, t := range d.threads {
		t.mu.Lock()
		t.syncFilesWithDisk()
		t.cleanUpOnLowDiskSpace()
		t.mu.Unlock()
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

func (d *Directory) getHTTPBlockfile(r *http.Request) (*blockfile.BlockFile, func(), error) {
	vals := r.URL.Query()
	threadID, err := strconv.Atoi(vals.Get("thread"))
	if threadID < 0 || threadID > len(d.threads) || err != nil {
		return nil, func() {}, fmt.Errorf("invalid thread")
	}
	thread := d.threads[threadID]
	name := vals.Get("name")
	thread.mu.RLock()
	file, ok := thread.files[name]
	if !ok {
		return nil, thread.mu.RUnlock, fmt.Errorf("invalid name")
	}
	return file, thread.mu.RUnlock, nil
}

// ExportDebugHandlers exports a few debugging handlers to an HTTP ServeMux.
func (d *Directory) ExportDebugHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/debug/files", func(w http.ResponseWriter, r *http.Request) {
		w = httplog.New(w, r, false)
		defer log.Print(w)
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
		w = httplog.New(w, r, false)
		defer log.Print(w)
		file, cleanup, err := d.getHTTPBlockfile(r)
		defer cleanup()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var start, finish []byte
		vals := r.URL.Query()
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
		w = httplog.New(w, r, false)
		defer log.Print(w)
		file, cleanup, err := d.getHTTPBlockfile(r)
		defer cleanup()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		base.PacketsToFile(file.AllPackets(), w)
	})
	mux.HandleFunc("/debug/positions", func(w http.ResponseWriter, r *http.Request) {
		w = httplog.New(w, r, true)
		defer log.Print(w)
		file, cleanup, err := d.getHTTPBlockfile(r)
		defer cleanup()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
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

// MinLastFileSeen returns the timestamp of the oldest among the newest files
// created by all threads.
func (d *Directory) MinLastFileSeen() time.Time {
	var t time.Time
	for _, thread := range d.threads {
		ls := thread.FileLastSeen()
		if t.IsZero() || ls.Before(t) {
			t = ls
		}
	}
	return t
}

// runStaleFileCheck watches files generated by stenotype to make sure it's
// regularly generating new files.  It will Kill() stenotype if it doesn't see
// at least one new file every maxFileLastSeenDuration in each thread directory.
func (d *Directory) runStaleFileCheck(cmd *exec.Cmd, done chan struct{}) {
	ticker := time.NewTicker(maxFileLastSeenDuration)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			v(2, "Checking stenotype for stale files...")
			diff := time.Now().Sub(d.MinLastFileSeen())
			if diff > maxFileLastSeenDuration {
				log.Printf("Restarting stenotype due to stale file.  Age: %v", diff)
				if err := cmd.Process.Kill(); err != nil {
					log.Fatalf("Failed to kill stenotype,  stale file found: ", err)
				}
			} else {
				v(2, "Stenotype up to date, last file update %v ago", diff)
			}
		case <-done:
			return
		}
	}
}

const (
	minStenotypeRuntimeForRestart = time.Minute
	maxFileLastSeenDuration       = time.Minute * 5
)

// runStenotypeOnce runs the stenotype binary a single time, returning any
// errors associated with its running.
func (d *Directory) runStenotypeOnce(outputTo io.Writer, outputDirectories []string) error {
	d.removeHiddenFiles(outputDirectories)
	cmd := d.Stenotype()
	done := make(chan struct{})
	defer close(done)
	// Start running stenotype.
	cmd.Stdout = outputTo
	cmd.Stderr = outputTo
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot start stenotype: %v", err)
	}
	go d.runStaleFileCheck(cmd, done)
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("stenotype wait failed: %v", err)
	}
	return fmt.Errorf("stenotype stopped")
}

// RunStenotype keeps the stenotype binary running, restarting it if necessary
// but trying not to allow crash loops.
func (d *Directory) RunStenotype(outputTo io.Writer, outputDirectories []string) {
	for {
		start := time.Now()
		v(1, "Running Stenotype")
		err := d.runStenotypeOnce(outputTo, outputDirectories)
		duration := time.Since(start)
		log.Printf("Stenotype stopped after %v: %v", duration, err)
		if duration < minStenotypeRuntimeForRestart {
			log.Fatalf("Stenotype ran for too little time, crashing to avoid stenotype crash loop")
		}
	}
}
