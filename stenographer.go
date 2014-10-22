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
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/google/stenographer/preadlib"
)

var (
	configFilename = flag.String("config", "", "File location to read configuration from")
	V              = preadlib.V
)

type Directory struct {
	threads int
}

func ReadConfig() (out preadlib.Config) {
	log.Printf("Reading config %q", *configFilename)
	data, err := ioutil.ReadFile(*configFilename)
	if err != nil {
		log.Fatalf("could not read config file %q: %v", *configFilename, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&out); err != nil {
		log.Fatalf("could not decode config file %q: %v", *configFilename, err)
	}
	return
}

func main() {
	flag.Parse()
	config := ReadConfig()
	V(1, "Using config:\n%v", config)
	dir, err := config.Directory()
	if err != nil {
		log.Fatalf("unable to set up stenographer directory: %v", err)
	}
	defer dir.Close()

	// Start running stenotype.
	cmd := config.Stenotype(dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Fatalf("cannot start stenotype: %v", err)
	}
	defer cmd.Process.Signal(os.Interrupt)
	go func() {
		if err := cmd.Wait(); err != nil {
			log.Fatalf("stenotype wait failed: %v", err)
		}
		log.Printf("stenotype stopped")
	}()

	http.HandleFunc("/dump/", func(w http.ResponseWriter, r *http.Request) {
		fpath := r.URL.Path[5:]
		log.Printf("dumping %q", fpath)
		w.Header().Set("Content-Type", "text/plain")
		dir.DumpIndex(fpath, w)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		log.Printf("requesting %q", r.URL.Path)
		packets := dir.Lookup(r.URL.Path[1:])
		if err := preadlib.PacketsToFile(packets, &buf); err != nil {
			http.Error(w, fmt.Sprintf("error: %v", err), 500)
		} else {
			w.Header().Set("Content-Type", "appliation/octet-stream")
			io.Copy(w, &buf)
		}
	})
	log.Println("serving on port %v", config.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("localhost:%d", config.Port), nil))
}
