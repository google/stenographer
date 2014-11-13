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

	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcapgo"
	"github.com/google/stenographer/base"
	"github.com/google/stenographer/config"
	"github.com/google/stenographer/query"
)

var configFilename = flag.String("config", "", "File location to read configuration from")

var v = base.V

func ReadConfig() *config.Config {
	var out config.Config
	log.Printf("Reading config %q", *configFilename)
	data, err := ioutil.ReadFile(*configFilename)
	if err != nil {
		log.Fatalf("could not read config file %q: %v", *configFilename, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&out); err != nil {
		log.Fatalf("could not decode config file %q: %v", *configFilename, err)
	}
	return &out
}

// snapLen is the max packet size we'll return in pcap files to users.
const snapLen = 65536

func PacketsToFile(in base.PacketChan, out io.Writer) error {
	w := pcapgo.NewWriter(out)
	w.WriteFileHeader(snapLen, layers.LinkTypeEthernet)
	count := 0
	defer in.Discard()
	for p := range in.Receive() {
		if len(p.Data) > snapLen {
			p.Data = p.Data[:snapLen]
		}
		if err := w.WritePacket(p.CaptureInfo, p.Data); err != nil {
			// This can happen if our pipe is broken, and we don't want to blow stack
			// traces all over our users when that happens, so Error/Exit instead of
			// Fatal.
			return fmt.Errorf("error writing packet: %v", err)
		}
		count++
	}
	return in.Err()
}

func main() {
	flag.Parse()
	conf := ReadConfig()
	v(1, "Using config:\n%v", conf)
	dir, err := conf.Directory()
	if err != nil {
		log.Fatalf("unable to set up stenographer directory: %v", err)
	}
	defer dir.Close()

	// Start running stenotype.
	cmd := conf.Stenotype(dir)
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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
		log.Printf("requesting %q", queryStr)
		packets := dir.Lookup(q)
		w.Header().Set("Content-Type", "appliation/octet-stream")
		PacketsToFile(packets, w)
	})
	log.Printf("Serving on port %v", conf.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("localhost:%d", conf.Port), nil))
}
