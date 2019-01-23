// Copyright 2019 Josh Liburdi and Google Inc. All rights reserved.
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
//
// Package rpc implements an optional, secure gRPC server for interacting
// with Stenographer. The gRPC service is defined in protobuf/steno.proto.
package rpc

import (
        "crypto/tls"
        "crypto/x509"
        "fmt"
        "io"
        "io/ioutil"
        "log"
        "net"
        "os"
        "os/exec"
        "path/filepath"

        "github.com/google/uuid"
        "google.golang.org/grpc"
        "google.golang.org/grpc/credentials"

        "github.com/google/stenographer/config"
        pb "github.com/google/stenographer/protobuf"
)


// gRPC server which takes the RpcConfig.
type stenographerServer struct {
        rpcCfg *config.RpcConfig
}

// Removes file from disk, primarily used to clean up during calls to RetrievePcap.
func removeFile(path string) {
        if err := os.Remove(path); err != nil {
                log.Printf("Rpc: Unable to remove file %s: %v", path, err)
        }
}

// Implements RetrievePcap call which takes a client query request, applies it
// to stenoread, and streams the PCAP back to the client.
func (s *stenographerServer) RetrievePcap(
        req *pb.PcapRequest,
        stream pb.Stenographer_RetrievePcapServer,
) error {
        if req.Query == "" {
                return nil
        }

        uid := uuid.New().String()
        if req.Uid != "" {
                uid = req.Uid
        }

        clientChunkSize := s.rpcCfg.ClientPcapChunkSize
        if req.ChunkSize != 0 {
                clientChunkSize = req.ChunkSize
        }

        clientMaxSize := s.rpcCfg.ClientPcapMaxSize
        if req.MaxSize != 0 {
                clientMaxSize = req.MaxSize
        }

        pcapPath := filepath.Join(s.rpcCfg.ServerPcapPath, fmt.Sprintf("%s.pcap", uid))
        cmd := exec.Command("stenoread", req.Query, "-w", pcapPath)
        if err := cmd.Run(); err != nil {
                log.Printf("Rpc: Unable to run stenoread command: %v", err)
                return nil
        }
        pcapStat, err := os.Stat(pcapPath)
        if err != nil {
                log.Printf("Rpc: Unable to stat PCAP file %s: %v", pcapPath, err)
                removeFile(pcapPath)
                return nil
        }
        // A PCAP file with no packets should always contain exactly 24 bytes
        if pcapStat.Size() == 24 {
                removeFile(pcapPath)
                return nil
        }
        pcapFile, err := os.Open(pcapPath)
        if err != nil {
                log.Printf("Rpc: Unable to open PCAP file %s: %v", pcapPath, err)
                removeFile(pcapPath)
                return nil
        }

        var pcapOffset int64 = 0
        buffer := make([]byte, clientChunkSize)
        for pcapOffset < clientMaxSize {
                if pcapOffset >= s.rpcCfg.ServerPcapMaxSize {
                        log.Printf("Rpc: Request %s hit size limit %d", uid, s.rpcCfg.ServerPcapMaxSize)
                        break
                }

                pcapOffset += clientChunkSize
                bytesRead, err := pcapFile.Read(buffer)
                if err != nil {
                        if err != io.EOF {
                                log.Printf("Rpc: Non-EOF error when reading PCAP %s: %v", pcapPath, err)
                        }
                        break
                }

                stream.Send(&pb.PcapResponse{Uid: uid, Pcap: buffer[:bytesRead]})
        }

        if err := pcapFile.Close(); err != nil {
                log.Printf("Rpc: Unable to close PCAP file %s: %v", pcapPath, err)
        }
        removeFile(pcapPath)

        return nil
}

// Called from main via goroutine, this function opens the gRPC port, loads
// certificates, and runs the gRPC server.
func RunStenorpc(rpcCfg *config.RpcConfig) {
        log.Print("Starting stenorpc")
        listener, err := net.Listen("tcp", fmt.Sprintf(":%d", rpcCfg.ServerPort))
        if err != nil {
                log.Printf("Rpc: Failed to start server: %v", err)
                return
        }

        cert, err := tls.LoadX509KeyPair(
                rpcCfg.ServerCert,
                rpcCfg.ServerKey,
        )
        if err != nil {
                log.Printf("Rpc: Failed to load server key pair: %v", err)
                return
        }
        pool := x509.NewCertPool()
        caCert, err := ioutil.ReadFile(rpcCfg.CaCert)
        if err != nil {
                log.Printf("Rpc: Failed to read CA certificate: %v", err)
                return
        }
        ok := pool.AppendCertsFromPEM(caCert)
        if !ok {
                log.Printf("Rpc: Failed to append CA certificate: %v", err)
                return
        }
        tlsCfg := &tls.Config{
                ClientAuth:   tls.RequireAndVerifyClientCert,
                Certificates: []tls.Certificate{cert},
                ClientCAs:    pool,
        }

        tlsCreds := grpc.Creds(credentials.NewTLS(tlsCfg))
        grpcServer := grpc.NewServer(tlsCreds)
        pb.RegisterStenographerServer(grpcServer, &stenographerServer{rpcCfg: rpcCfg})
        if err := grpcServer.Serve(listener); err != nil {
                log.Printf("Rpc: Failed to run gRPC server: %v", err)
                return
        }
}
