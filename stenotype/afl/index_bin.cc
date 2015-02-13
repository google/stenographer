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

// This binary provides an entry point into Index::Process for the 'afl'
// (american fuzzy lop) fuzzer.

#include <stdio.h>        // fprintf(), stderr
#include <stdlib.h>       // exit()
#include <fcntl.h>        // open()
#include <unistd.h>       // read()
#include <leveldb/env.h>  // WritableFile

#include "util.h"
#include "packets.h"
#include "index.h"

class NullFile : public leveldb::WritableFile {
 public:
  NullFile() {}
  virtual ~NullFile() {}
  leveldb::Status Append(const leveldb::Slice& data) override {
    return leveldb::Status::OK();
  }
  leveldb::Status Close() override { return leveldb::Status::OK(); }
  leveldb::Status Flush() override { return leveldb::Status::OK(); }
  leveldb::Status Sync() override { return leveldb::Status::OK(); }
};

size_t ReadFile(char* filename, char* buffer, size_t len) {
  fprintf(stderr, "Reading %s\n", filename);
  int fd = open(filename, O_RDONLY);
  if (fd <= 0) {
    fprintf(stderr, "could not open file\n");
    exit(1);
  }
  char* start = buffer;
  char* limit = start + len;
  while (start < limit) {
    int n = read(fd, start, limit - start);
    if (n < 0) {
      fprintf(stderr, "failed to read file\n");
      exit(1);
    }
    if (n == 0) break;
    start += n;
  }
  close(fd);
  return start - buffer;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "need filename\n");
    exit(1);
  }

  char buffer[1 << 20];  // 1MB
  size_t got = ReadFile(argv[1], buffer, 1 << 20);

  st::Packet p;
  p.length = got;
  p.data = leveldb::Slice(buffer, got);
  p.offset_in_block = 1;

  st::Index idx("/tmp", 123);
  idx.Process(p, 0);
  NullFile file;
  idx.WriteTo(&file);
  return 0;
}
