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

// Binary stenographer reads packets from the given filename based on a set of
// IPs and spits them out via STDOUT as pcap data, which should be able to be
// piped into tcpdump.
package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/google/stenographer/base"
	"github.com/google/stenographer/config"
	"github.com/google/stenographer/httplog"
	"github.com/google/stenographer/query"
	"golang.org/x/net/context"

	_ "net/http/pprof" // server debugging info in /debug/pprof/*
)

var (
	configFilename = flag.String(
		"config",
		"/etc/stenographer/config",
		"File location to read configuration from")

	logToSyslog = flag.Bool(
		"syslog", true, "If true, log to syslog.  Otherwise, log to stderr")

	// Verbose logging.
	v = base.V
)

const (
	minStenotypeRuntimeForRestart = time.Minute
	maxFileLastSeenDuration       = time.Minute * 5
	snapLen                       = 65536 // Max packet size we return in pcap files to users.
)

type stenotypeRunner struct {
	cmd  *exec.Cmd
	dir  *config.Directory
	stop chan bool
}

func newStenotypeRunner(cmd *exec.Cmd, dir *config.Directory) *stenotypeRunner {
	sc := &stenotypeRunner{
		cmd:  cmd,
		dir:  dir,
		stop: make(chan bool, 1),
	}
	// Stenotype is initially stopped.
	sc.stop <- true
	return sc
}

// ReadConfig reads in the config specified by the --config flag.
func ReadConfig() *config.Config {
	c, err := config.ReadConfigFile(*configFilename)
	if err != nil {
		log.Fatal(err.Error())
	}
	return c
}

func (sr *stenotypeRunner) runStaleFileCheck() {
	proc := sr.cmd.Process
	ticker := time.NewTicker(maxFileLastSeenDuration)
	done := make(chan bool)
	defer ticker.Stop()

	go func() {
		sr.cmd.Wait()
		done <- true
	}()

	for {
		select {
		case <-ticker.C:
			v(1, "Checking stenotype for stale files...")
			diff := time.Now().Sub(sr.dir.MinLastFileSeen())
			if diff > maxFileLastSeenDuration {
				if err := proc.Kill(); err != nil {
					log.Fatalf("Failed to kill stenotype,  stale file found: ", err)
				}
				log.Printf("Restarting stenotype due to stale file.  Age: %v", diff)
				sr.stop <- true
			} else {
				log.Printf("Stenotype up to date, last file update %v ago", diff)
			}
		case <-done:
			return
		}
	}
}

var stenotypeOutput io.Writer = os.Stderr

// runStenotypeOnce runs the stenotype binary a single time, returning any
// errors associated with its running.
func (sr *stenotypeRunner) runStenotypeOnce() error {
	// Start running stenotype.
	sr.cmd.Stdout = os.Stdout
	sr.cmd.Stderr = os.Stderr
	if err := sr.cmd.Start(); err != nil {
		return fmt.Errorf("cannot start stenotype: %v", err)
	}
	go sr.runStaleFileCheck()
	defer sr.cmd.Process.Signal(os.Interrupt)
	if err := sr.cmd.Wait(); err != nil {
		return fmt.Errorf("stenotype wait failed: %v", err)
	}
	return fmt.Errorf("stenotype stopped")
}

// runStenotype keeps the stenotype binary running, restarting it if necessary
// but trying not to allow crash loops.
func (sr *stenotypeRunner) runStenotype() {
	for {
		start := time.Now()
		log.Printf("Running Stenotype...")
		err := sr.runStenotypeOnce()
		duration := time.Since(start)
		log.Printf("Stenotype stopped after %v: %v", duration, err)
		if duration < minStenotypeRuntimeForRestart {
			log.Fatalf("Stenotype ran for too little time, crashing to avoid stenotype crash loop")
		}
	}
}

func main() {
	flag.Parse()

	// Set up syslog logging
	if *logToSyslog {
		logwriter, err := syslog.New(syslog.LOG_USER|syslog.LOG_INFO, "stenographer")
		if err != nil {
			log.Fatalf("could not set up syslog logging")
		}
		log.SetOutput(logwriter)
		stenotypeOutput = logwriter // for stenotype
	}

	runtime.GOMAXPROCS(runtime.NumCPU() * 2)
	conf := ReadConfig()
	v(1, "Using config:\n%v", conf)
	dir, err := conf.Directory()
	cmd := conf.Stenotype(dir)
	if err != nil {
		log.Fatalf("unable to set up stenographer directory: %v", err)
	}
	defer dir.Close()

	// Start stenotype with period run check
	sr := newStenotypeRunner(cmd, dir)
	go sr.runStenotype()
	go sr.runStaleFileCheck()

	// HTTP handling
	conf.ExportDebugHandlers(http.DefaultServeMux)
	dir.ExportDebugHandlers(http.DefaultServeMux)
	http.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		w = httplog.New(w, r, true)
		defer log.Print(w)
		queryBytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "could not read request body", http.StatusBadRequest)
			return
		}
		q, err := query.NewQuery(string(queryBytes))
		if err != nil {
			http.Error(w, "could not parse query", http.StatusBadRequest)
			return
		}
		ctx, cancel := contextFromHTTP(w, r)
		defer cancel()
		packets := dir.Lookup(ctx, q)
		w.Header().Set("Content-Type", "appliation/octet-stream")
		base.PacketsToFile(packets, w)
	})
	log.Fatal(conf.Serve())
}

// contextFromHTTP returns a new context.Content that cancels when the
// underlying http.ResponseWriter closes.
func contextFromHTTP(w http.ResponseWriter, r *http.Request) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	if closer, ok := w.(http.CloseNotifier); ok {
		go func() {
			select {
			case <-closer.CloseNotify():
				log.Printf("Detected closed HTTP connection, canceling query")
				cancel()
			case <-ctx.Done():
			}
		}()
	}
	return ctx, cancel
}
