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

#include <stdio.h>   // fprintf(), stderr
#include <fcntl.h>   // open()
#include <unistd.h>  // read()

#include "util.h"
#include "packets.h"
#include "index.h"

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "need filename\n");
    exit(1);
  }
  int fd = open(argv[1], O_RDONLY);
  if (fd <= 0) {
    fprintf(stderr, "could not open file\n");
    exit(1);
  }
  char buffer[8 << 20];  // 8MB
  char* start = buffer;
  int left = 8 << 20;
  while (true) {
    int n = read(fd, start, left);
    if (n < 0) {
      fprintf(stderr, "failed to read file\n");
      exit(1);
    }
    if (n == 0) break;
    start += n;
    left -= n;
  }
  int size = start - buffer;
  st::Packet p;
  p.length = size;
  p.data = leveldb::Slice(buffer, size);
  p.offset_in_block = 1;

  st::Index idx("/tmp", 123);
  idx.Process(p, 0);
}
