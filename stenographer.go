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
	"log"
	"log/syslog"
	"net/http"
	"os"
	"runtime"

	"github.com/google/stenographer/base"
	"github.com/google/stenographer/config"
	"github.com/google/stenographer/env"

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

func main() {
	flag.Parse()

	stenotypeOutput := io.Writer(os.Stderr)

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

	conf, err := config.ReadConfigFile(*configFilename)
	if err != nil {
		log.Fatal(err.Error())
	}

	v(1, "Using config:\n%+v", conf)
	env, err := env.New(*conf)
	if err != nil {
		log.Fatalf("unable to set up stenographer environment: %v", err)
	}
	env.StenotypeOutput = stenotypeOutput
	defer env.Close()

	go env.RunStenotype()

	env.ExportDebugHandlers(http.DefaultServeMux)
	log.Fatal(env.Serve())
}
