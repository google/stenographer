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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

const (
	bits     = 2048
	validFor = 365 * 24 * time.Hour
)

// WriteNewCerts generates a self-signed certificate pair for use in
// locally authorizing clients.  If 'server' is true, it writes out certs
// which can be used to verify the server, otherwise it writes out certs
// clients can use to authorize themselves to the server.
func WriteNewCerts(certFile, keyFile string, server bool) error {
	// Implementation mostly taken from http://golang.org/src/pkg/crypto/tls/generate_cert.go
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Stenographer"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(validFor),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IsCA:                  true, // we're self-signed.
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("Failed to create certificate: %v", err)
	}

	// Actually start writing.
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to open %q for writing: %s", certFile, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("could not encode pem: %v", err)
	}
	if err := certOut.Close(); err != nil {
		return fmt.Errorf("could not close cert file: %v", err)
	}

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %q for writing: %v", keyFile, err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return fmt.Errorf("could not encode key: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		return fmt.Errorf("could not close key file: %v", err)
	}
	return nil
}

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
