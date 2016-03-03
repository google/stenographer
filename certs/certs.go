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

// Package certs provides helper libraries for generating self-signed
// certificates, which we use locally for authorizing users to read
// packet data.
package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// ClientVerifyingTLSConfig returns a TLS config which verifies that clients
// have a certificate signed by the CA certificate in the certFile.
func ClientVerifyingTLSConfig(certFile string) (*tls.Config, error) {
	// Test cert file
	var cert *x509.Certificate
	if certBytes, err := ioutil.ReadFile(certFile); err != nil {
		return nil, fmt.Errorf("could not read cert file: %v", err)
	} else if block, _ := pem.Decode(certBytes); block == nil {
		return nil, fmt.Errorf("could not get cert pem block: %v", err)
	} else if cert, err = x509.ParseCertificate(block.Bytes); err != nil {
		return nil, fmt.Errorf("could not parse cert: %v", err)
	}
	cas := x509.NewCertPool()
	cas.AddCert(cert)
	return &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  cas,
	}, nil
}
