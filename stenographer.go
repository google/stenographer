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
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/stenographer/preadlib"
)

var (
	dirbase = flag.String("dir", "", "file to read from")
	V       = preadlib.V
)

func main() {
	flag.Parse()
	log.Printf("Starting")

	var blockfiles []*preadlib.BlockFile
	for i := 0; ; i++ {
		dir := fmt.Sprintf("%s/%d", *dirbase, i)
		log.Printf("processing directory %q", dir)
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				log.Printf("%q does not exist, not looking for new directories", dir)
				break
			} else {
				log.Fatalf("could not read %q: %v", dir, err)
			}
		}
		for _, file := range files {
			V(1, "checking file %q", file.Name())
			if file.IsDir() {
				continue
			}
			filename := file.Name()
			if filename[0] != '.' {
				filename = filepath.Join(dir, filename)
				blockfile, err := preadlib.NewBlockFile(filename)
				if err != nil {
					log.Printf("error opening %q: %v", filename, err)
				} else {
					blockfiles = append(blockfiles, blockfile)
				}
			}
		}
	}

	query := strings.Join(flag.Args(), " ")
	var inputs []<-chan preadlib.Packet
	for _, file := range blockfiles {
		inputs = append(inputs, file.Lookup(query))
	}
	if err := preadlib.PacketsToFile(preadlib.MergePackets(inputs), os.Stdout); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
