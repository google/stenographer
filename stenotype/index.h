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

#ifndef EXPERIMENTAL_USERS_GCONNELL_AFPACKET_INDEX_H_
#define EXPERIMENTAL_USERS_GCONNELL_AFPACKET_INDEX_H_

#include <string.h>  // memcpy()

#include <map>
#include <vector>

#include <leveldb/slice.h>

#include "packets.h"
#include "util.h"

namespace st {

// SliceSet is a utility function for storing unique Slices in a
// location whose persistence we can control.  We use it to store the bytes
// backing an IP address without having to create new strings in memory to store
// those IPs.
class SliceSet {
 private:
  struct Buffer {
    Buffer(Buffer* l, size_t size) : last(l), total(size), remaining(size) {
      buffer = new char[size];
      current = buffer;
      LOG(V1) << "New stringslice is " << (total >> 20) << "MB";
    }

    void Reset() {
      if (last) {
        delete last;
      }
      last = NULL;
      remaining = total;
      current = buffer;
      LOG(V1) << "Reset stringslice to " << (total >> 20) << "MB";
    }

    ~Buffer() {
      Reset();
      delete[] buffer;
    }

    void Add(leveldb::Slice* s) {
      CHECK(remaining >= s->size());
      remaining -= s->size();
      memcpy(current, s->data(), s->size());
      *s = leveldb::Slice(current, s->size());
      current += s->size();
    }

    Buffer* last;
    char* buffer;
    char* current;
    size_t total;
    size_t remaining;
  };

 public:
  SliceSet(size_t initial) : last_size_(initial) {
    current_ = new Buffer(NULL, initial);
  }
  virtual ~SliceSet() { delete current_; }
  leveldb::Slice Store(leveldb::Slice s) {
    if (current_->remaining < s.size()) {
      last_size_ *= 2;
      if (last_size_ < s.size()) {
        last_size_ = s.size();
      }
      current_ = new Buffer(current_, last_size_);
    }
    current_->Add(&s);
    return s;
  }
  virtual void Reset() { current_->Reset(); }

 private:
  Buffer* current_;
  size_t last_size_;
};

// Index is a simple proof-of-concept for indexing packets seen by stenotype.
// Its main purpose currently is to determine which indexes we want to use and
// provide a proving ground for things like "how many IPs that we see are
// unique", etc, to give us an idea about how much data we'll actually need to
// write to disk.
class Index {
 public:
  explicit Index(const std::string& dirname, int64_t micros)
      : dirname_(dirname),
        micros_(micros),
        packets_(0),
        ip_pieces_(1 << 20) {}  // Start slice set off at 1MB.
  virtual ~Index() {}

  void Process(const Packet& p, int64_t block_offset);
  Error Flush();

 private:
  void AddIPv4(uint32_t ip, uint32_t pos);
  void AddIPv6(leveldb::Slice ip, uint32_t pos);
  void AddProtocol(uint8_t proto, uint32_t pos);
  void AddPort(uint16_t port, uint32_t pos);
  void AddVLAN(uint16_t port, uint32_t pos);
  void AddMPLS(uint32_t mpls, uint32_t pos);

  std::string dirname_;
  int64_t micros_;
  int64_t packets_;
  SliceSet ip_pieces_;
  std::map<uint32_t, std::vector<uint32_t>> ip4_;
  std::map<leveldb::Slice, std::vector<uint32_t>> ip6_;
  std::map<uint8_t, std::vector<uint32_t>> proto_;
  std::map<uint16_t, std::vector<uint32_t>> port_;
  std::map<uint16_t, std::vector<uint32_t>> vlan_;
  std::map<uint32_t, std::vector<uint32_t>> mpls_;

  DISALLOW_COPY_AND_ASSIGN(Index);
};

}  // namespace st

#endif  // EXPERIMENTAL_USERS_GCONNELL_AFPACKET_INDEX_H_
