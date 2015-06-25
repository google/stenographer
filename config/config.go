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
	"os"
	"net"

	"github.com/google/stenographer/base"
)

var v = base.V // verbose logging
const (
	defaultDiskSpacePercentage = 10

	// By default, ext3 has issues with >32k files, so we go for something less
	// than that.
	defaultMaxDirectoryFiles = 30000
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

// Config is a json-decoded configuration for running stenographer.
type Config struct {
	StenotypePath string
	Threads       []ThreadConfig
	Interface     string
	Flags         []string
	Port          int
	Host		  string // Location to listen.
	CertPath      string // Directory where client and server certs are stored.
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
	for _, thread := range c.Threads {
		if _, err := os.Stat(thread.PacketsDirectory); err != nil {
			return fmt.Errorf("invalid packets directory %q in configuration: %v", thread.PacketsDirectory, err)
		}
		if _, err := os.Stat(thread.IndexDirectory); err != nil {
			return fmt.Errorf("invalid index directory %q in configuration: %v", thread.IndexDirectory, err)
		}
	}

	if host := net.ParseIP(c.Host); host == nil {
		return fmt.Errorf("invalid listening location %q in configuration", c.Host)
	}

	return nil
}
