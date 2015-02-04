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
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"runtime"

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
	snapLen = 65536 // Max packet size we return in pcap files to users.
)

// ReadConfig reads in the config specified by the --config flag.
func ReadConfig() *config.Config {
	c, err := config.ReadConfigFile(*configFilename)
	if err != nil {
		log.Fatal(err.Error())
	}
	return c
}

func main() {
	flag.Parse()

  var stenotypeOutput io.Writer = os.Stderr

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
	runtime.SetBlockProfileRate(1000)
	conf := ReadConfig()
	v(1, "Using config:\n%v", conf)
	dir, err := conf.Directory()
	if err != nil {
		log.Fatalf("unable to set up stenographer directory: %v", err)
	}
	defer dir.Close()

	go dir.RunStenotype(stenotypeOutput)

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
