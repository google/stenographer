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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/stenographer/base"
	"github.com/google/stenographer/blockfile"
	"github.com/google/stenographer/query"
)

var v = base.V // verbose logging
const (
	packetPrefix           = "PKT"
	indexPrefix            = "IDX"
	minDiskSpacePercentage = 10
	fileSyncFrequency      = 15 * time.Second
	cleanUpFrequency       = 45 * time.Second
)

type ThreadConfig struct {
	PacketsDirectory string
	IndexDirectory   string
	MinDiskFree      int `json:",omitempty"`
}

type Config struct {
	StenotypePath string
	Threads       []ThreadConfig
	Interface     string
	Flags         []string
	Port          int
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

func (st *stenotypeThread) createSymlinks(config *ThreadConfig) error {
	if err := os.Symlink(config.PacketsDirectory, st.packetPath); err != nil {
		return fmt.Errorf("couldn't create symlink for thread %d to directory %q: %v",
			st.id, config.PacketsDirectory, err)
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
	for _, file := range st.listPacketFilesOnDisk() {
		filename := file.Name()
		if st.files[filename] != nil {
			continue
		}
		if err := st.trackNewFile(filename); err != nil {
			log.Printf("%v", err)
			continue
		}
		newFilesCnt++
	}
	if newFilesCnt > 0 {
		log.Printf("Found %d new blockfiles", newFilesCnt)
	}
}

func (st *stenotypeThread) listPacketFilesOnDisk() []os.FileInfo {
	files, err := ioutil.ReadDir(st.packetPath)
	if err != nil {
		log.Printf("could not read dir %q: %v", st.packetPath, err)
		return nil
	}
	var out []os.FileInfo
	for _, file := range files {
		if file.IsDir() || file.Name()[0] == '.' {
			continue
		}
		out = append(out, file)
	}
	return out
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
			log.Printf("could not get the free disk percentage for %q: %v", st.packetPath, err)
			return
		}
		if df > st.minDiskFree {
			return
		}
		log.Printf("disk usage is high for thread %d (packet path=%q): %d%% free\n",
			st.id, st.packetPath, df)
		if err := st.deleteOlderThreadFiles(); err != nil {
			log.Printf("could not free up space by deleting old files: %v", err)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (st *stenotypeThread) deleteOlderThreadFiles() error {
	st.mu.Lock()
	defer st.mu.Unlock()

	oldestFile := st.getOldestFile()
	if oldestFile == "" {
		return fmt.Errorf("no files tracked for thread %d", st.id)
	}
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
	b := st.files[filename]
	if b == nil {
		return fmt.Errorf("trying to untrack file %q for thread %d, but that file is not monitored",
			st.getPacketFilePath(filename), st.id)
	}
	v(1, "old blockfile %q", b.Name())
	b.Close()
	delete(st.files, filename)
	return nil
}

func (st *stenotypeThread) lookup(q query.Query) base.PacketChan {
	st.mu.RLock()
	defer st.mu.RUnlock()
	var inputs []base.PacketChan
	for _, file := range st.files {
		inputs = append(inputs, file.Lookup(q))
	}
	return base.MergePacketChans(inputs)
}

func (st *stenotypeThread) getBlockFile(name string) *blockfile.BlockFile {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.files[name]
}

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
		if thread.MinDiskFree <= 0 {
			out.Threads[i].MinDiskFree = minDiskSpacePercentage
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
		st.minDiskFree = threadConfig.MinDiskFree
		if err := st.createSymlinks(&threadConfig); err != nil {
			return nil, err
		}
		threads[i] = st
	}
	return newDirectory(dirname, threads), nil
}

func (c Config) Stenotype(d *Directory) *exec.Cmd {
	log.Printf("Starting stenotype")
	args := append(c.args(), fmt.Sprintf("--dir=%s", d.Path()))
	v(1, "Starting as %q with args %q", c.StenotypePath, args)
	return exec.Command(c.StenotypePath, args...)
}

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
	go d.callEvery(d.detectNewFiles, fileSyncFrequency)
	go d.callEvery(d.cleanUpDisksIfneeded, cleanUpFrequency)
	return d
}

func (d *Directory) Close() error {
	return os.RemoveAll(d.name)
}

func (d *Directory) callEvery(cb func(), freq time.Duration) {
	ticker := time.NewTicker(freq)
	defer ticker.Stop()
	for {
		select {
		case <-d.done:
			return
		case <-ticker.C:
			cb()
		}
	}
}

func (d *Directory) detectNewFiles() {
	for _, t := range d.threads {
		t.syncFilesWithDisk()
	}
}

func (d *Directory) cleanUpDisksIfneeded() {
	for _, t := range d.threads {
		t.cleanUpOnLowDiskSpace()
	}
}

func (d *Directory) Path() string {
	return d.name
}

func (d *Directory) Lookup(q query.Query) base.PacketChan {
	var inputs []base.PacketChan
	for _, thread := range d.threads {
		inputs = append(inputs, thread.lookup(q))
	}
	return base.MergePacketChans(inputs)
}
