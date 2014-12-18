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

package certs

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteCerts(t *testing.T) {
	dir, err := ioutil.TempDir("", "stenocerts")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := WriteNewCerts(certFile, keyFile, true); err != nil {
		t.Errorf("unable to generate certs files: %v", err)
	}
	// Test cert file
	if certBytes, err := ioutil.ReadFile(certFile); err != nil {
		t.Errorf("could not read cert file: %v", err)
	} else if block, _ := pem.Decode(certBytes); block == nil {
		t.Errorf("could not get cert pem block: %v", err)
	} else if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Errorf("could not parse cert: %v", err)
	}
	// Test key file
	if keyBytes, err := ioutil.ReadFile(keyFile); err != nil {
		t.Errorf("could not read key file: %v", err)
	} else if block, _ := pem.Decode(keyBytes); block == nil {
		t.Errorf("could not get key pem block: %v", err)
	} else if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		t.Errorf("could not parse key: %v", err)
	}
}
