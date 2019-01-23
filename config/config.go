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

// Package config contains the configuration file format for stenographer's main
// configuration file.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"

	"github.com/google/stenographer/base"
)

var v = base.V // verbose logging
const (
	defaultDiskSpacePercentage = 10

	// By default, ext3 has issues with >32k files, so we go for something less
	// than that.
	defaultMaxDirectoryFiles = 30000

	defaultMaxOpenFiles = 100000
)

// ThreadConfig is a json-decoded configuration for each stenotype thread,
// detailing where it should store data and how much disk space it should keep
// available on each disk.
type ThreadConfig struct {
	PacketsDirectory   string
	IndexDirectory     string
	DiskFreePercentage int `json:",omitempty"`
	MaxDirectoryFiles  int `json:",omitempty"`
}

// RpcConfig is a json-decoded configuration for running the gRPC server.
type RpcConfig struct {
        CaCert                  string
        ServerKey               string
        ServerCert              string
        ServerPort              int
        ServerPcapPath          string
        ServerPcapMaxSize       int64
        ClientPcapChunkSize     int64
        ClientPcapMaxSize       int64
}

// Config is a json-decoded configuration for running stenographer.
type Config struct {
        Rpc           *RpcConfig
	StenotypePath string
	Threads       []ThreadConfig
	Interface     string
	Flags         []string
	Port          int
	Host          string // Location to listen.
	CertPath      string // Directory where client and server certs are stored.
	MaxOpenFiles  int    // Max number of file descriptors opened at once
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
	if out.MaxOpenFiles <= 0 {
		out.MaxOpenFiles = defaultMaxOpenFiles
	}
	for i, thread := range out.Threads {
		if thread.DiskFreePercentage <= 0 {
			out.Threads[i].DiskFreePercentage = defaultDiskSpacePercentage
		}
		if thread.MaxDirectoryFiles <= 0 {
			out.Threads[i].MaxDirectoryFiles = defaultMaxDirectoryFiles
		}
	}
	return &out, nil
}

// Validate checks the configuration for common errors.
func (c Config) Validate() error {
	for n, thread := range c.Threads {
		if thread.PacketsDirectory == "" {
			return fmt.Errorf("No packet directory specified for thread %d in configuration", n)
		}
		if thread.IndexDirectory == "" {
			return fmt.Errorf("No index directory specified for thread %d in configuration", n)
		}
	}

	if host := net.ParseIP(c.Host); host == nil {
		return fmt.Errorf("invalid listening location %q in configuration", c.Host)
	}

	return nil
}
