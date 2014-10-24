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
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/google/stenographer/base"
	"github.com/google/stenographer/blockfile"
)

var v = base.V // verbose logging

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
	v(1, "Starting as %q with args %q", c.StenotypePath, args)
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
	files   map[fileKey]*blockfile.BlockFile
	done    chan bool
}

func newDirectory(dirname string, threads int) *Directory {
	d := &Directory{
		name:    dirname,
		threads: threads,
		done:    make(chan bool),
		files:   map[fileKey]*blockfile.BlockFile{},
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
			bf, err := blockfile.NewBlockFile(filepath)
			if err != nil {
				log.Printf("could not open blockfile %q: %v", filepath, err)
				continue
			}
			v(1, "new blockfile %q", filepath)
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
		if !b.StillAtOriginalPath() {
			v(1, "old blockfile %q", b.Name())
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

func (d *Directory) Lookup(query string) base.PacketChan {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var inputs []base.PacketChan
	for _, file := range d.files {
		inputs = append(inputs, file.Lookup(query))
	}
	return base.MergePacketChans(inputs)
}

func (d *Directory) DumpIndex(name string, out io.Writer) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, file := range d.files {
		log.Printf("%q %q", file.Name(), name)
		if file.Name() == name {
			file.DumpIndex(out)
			return
		}
	}
}
