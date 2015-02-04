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

#include "index.h"

#include <memory>
#include <string>

#include <netinet/if_ether.h>  // ethhdr
#include <netinet/in.h>        // ntohs(), ntohl()
#include <netinet/tcp.h>       // tcphdr
#include <netinet/udp.h>       // udphdr
#include <netinet/ip.h>        // iphdr
#include <netinet/ip6.h>       // ip6_hdr

#include <leveldb/env.h>
#include <leveldb/slice.h>
#include <leveldb/status.h>
#include <leveldb/table_builder.h>

namespace leveldb {

// Augment leveldb::Slice just slightly, so we can use it inside ordered
// data structures like our in-memory trees.
bool operator<(const leveldb::Slice& a, const leveldb::Slice& b) {
  return a.compare(b) < 0;
}

}  // namespace leveldb

namespace st {

void Index::Process(const Packet& p, int64_t block_offset) {
  packets_++;
  int64_t packet_offset = block_offset + p.offset_in_block;
  const char* start = p.data.data();
  const char* limit = start + p.data.size();
  if (start + sizeof(struct ethhdr) > limit) {
    return;
  }
  auto eth = reinterpret_cast<const struct ethhdr*>(start);
  start += sizeof(struct ethhdr);
  auto type = ntohs(eth->h_proto);
  if (type == ETH_P_8021Q) {
    if (start + 4 > limit) {
      return;
    }
    type = ntohs(*reinterpret_cast<const uint16_t*>(start + 2));
    start += 4;
  }
  uint8_t protocol = 0;
  switch (type) {
    case ETH_P_IP: {
      if (start + sizeof(struct iphdr) > limit) {
        return;
      }
      auto ip4 = reinterpret_cast<const struct iphdr*>(start);
      AddIP(leveldb::Slice(reinterpret_cast<const char*>(&ip4->saddr), 4),
            packet_offset);
      AddIP(leveldb::Slice(reinterpret_cast<const char*>(&ip4->daddr), 4),
            packet_offset);
      size_t len = ip4->ihl;
      len *= 4;
      if (len < 20) return;
      protocol = ip4->protocol;
      start += len;
      break;
    }
    case ETH_P_IPV6: {
      if (start + sizeof(struct ip6_hdr) > limit) {
        return;
      }
      auto ip6 = reinterpret_cast<const struct ip6_hdr*>(start);
      protocol = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
      start += sizeof(struct ip6_hdr);
      AddIP(leveldb::Slice(reinterpret_cast<const char*>(&ip6->ip6_src), 16),
            packet_offset);
      AddIP(leveldb::Slice(reinterpret_cast<const char*>(&ip6->ip6_dst), 16),
            packet_offset);
      bool ip6extensions = true;
      while (ip6extensions) {
        switch (protocol) {
          case IPPROTO_FRAGMENT: {
            if (start + sizeof(struct ip6_frag) > limit) {
              return;
            }
            auto ip6frag = reinterpret_cast<const struct ip6_frag*>(start);
            if (ntohs(ip6frag->ip6f_offlg) & 0xfff8) {
              // If we're not the first fragment, break out of the loop so we
              // can store the IPs we have but recognize in the protocol switch
              // later on that we don't know what this packet is.
              ip6extensions = false;
              break;
            }
            // otherwise, fall through to treating this like any other
            // extention.
          }
#ifdef IPPROTO_MH
          case IPPROTO_MH:
#endif
          case IPPROTO_HOPOPTS:
          case IPPROTO_ROUTING:
          case IPPROTO_DSTOPTS: {
            if (start + sizeof(struct ip6_ext) > limit) {
              return;
            }
            auto ip6ext = reinterpret_cast<const struct ip6_ext*>(start);
            protocol = ip6ext->ip6e_nxt;
            start += (ip6ext->ip6e_len + 1) * 8;
            break;
          }
          default:
            ip6extensions = false;
        }
      }
      break;
    }
    default:
      return;
  }
  AddProtocol(protocol, packet_offset);
  switch (protocol) {
    case IPPROTO_TCP: {
      if (start + sizeof(struct tcphdr) > limit) {
        return;
      }
      auto tcp = reinterpret_cast<const struct tcphdr*>(start);
      AddPort(ntohs(tcp->source), packet_offset);
      AddPort(ntohs(tcp->dest), packet_offset);
      break;
    }
    case IPPROTO_UDP: {
      if (start + sizeof(struct udphdr) > limit) {
        return;
      }
      auto udp = reinterpret_cast<const struct udphdr*>(start);
      AddPort(ntohs(udp->source), packet_offset);
      AddPort(ntohs(udp->dest), packet_offset);
      break;
    }
    default:
      return;
  }
}

namespace {

// Simple, horribly inefficient, and slow.  You've been warned.
std::string Hex(const char* start, int size) {
  const char* vals = "0123456789ABCDEF";
  std::string out;
  for (const char* limit = start + size; start < limit; start++) {
    unsigned char c = *start;
    out.append(1, vals[c >> 4]);
    out.append(1, vals[c & 0x7]);
  }
  return out;
}

void WriteToIndex(char first, const char* start, int size, int64_t pos,
                  leveldb::TableBuilder* ss) {
  VLOG(10) << "Writing index " << int(first) << ":*" << size << ")"
           << Hex(start, size) << "=" << pos;
  char buf[1 +   // First byte is type of index (ip4, ip6, proto, etc)
           4 +   // Last 4 bytes are position in the blockfile
           16];  // Middle 1-16 bytes are type-specific index values.
  CHECK(size <= 16);
  CHECK(pos < int64_t(1) << 32);
  buf[0] = first;
  memcpy(buf + 1, start, size);
  uint32_t pos32 = htonl(pos);
  memcpy(buf + 1 + size, reinterpret_cast<const char*>(&pos32), 4);
  ss->Add(leveldb::Slice(buf, size + 1 + 4), leveldb::Slice());
}

// Should be incremented for backwards-incompatible changes.
const uint16_t kIndexVersionNumberMajor = 1;
// Should be incremented for backwards-compatible changes.
const uint16_t kIndexVersionNumberMinor = 0;
const uint32_t kIndexVersionNumber =
    (uint32_t(kIndexVersionNumberMajor) << 16) | kIndexVersionNumberMinor;

const char kIndexVersion = 0;
const char kIndexProtocol = 1;
const char kIndexPort = 2;
const char kIndexIPv4 = 4;
const char kIndexIPv6 = 6;

}  // namespace

Error Index::Flush() {
  leveldb::WritableFile* file;
  std::string filename = HiddenFile(dirname_, micros_);
  auto status = leveldb::Env::Default()->NewWritableFile(filename, &file);
  std::unique_ptr<leveldb::WritableFile> cleaner(file);
  if (!status.ok()) {
    return ERROR("could not open '" + filename + "': " + status.ToString());
  }

  leveldb::Options options;
  options.compression = leveldb::kNoCompression;
  leveldb::TableBuilder index_ss(options, file);

  // The first entry we write is the version number that defines
  // the format for this file.
  WriteToIndex(kIndexVersion, NULL, 0, kIndexVersionNumber, &index_ss);

  for (auto iter : proto_) {
    int64_t last_pos = 0;
    for (int64_t pos : iter.second) {
      if (pos > last_pos) {
        WriteToIndex(kIndexProtocol, reinterpret_cast<const char*>(&iter.first),
                     1, pos, &index_ss);
      }
      last_pos = pos;
    }
  }
  for (auto iter : port_) {
    uint16_t port = htons(iter.first);
    int64_t last_pos = 0;
    for (int64_t pos : iter.second) {
      if (pos > last_pos) {
        WriteToIndex(kIndexPort, reinterpret_cast<const char*>(&port), 2, pos,
                     &index_ss);
      }
      last_pos = pos;
    }
  }
  for (auto iter : ip4_) {
    int64_t last_pos = 0;
    for (int64_t pos : iter.second) {
      if (pos > last_pos) {
        WriteToIndex(kIndexIPv4, iter.first.data(), 4, pos, &index_ss);
      }
      last_pos = pos;
    }
  }
  for (auto iter : ip6_) {
    int64_t last_pos = 0;
    for (int64_t pos : iter.second) {
      if (pos > last_pos) {
        WriteToIndex(kIndexIPv6, iter.first.data(), 16, pos, &index_ss);
      }
      last_pos = pos;
    }
  }
  auto finished = index_ss.Finish();
  if (!finished.ok()) {
    return ERROR("could not finish writing index table '" + filename + "': " +
                 finished.ToString());
  }
  auto closed = file->Close();
  if (!closed.ok()) {
    return ERROR("could not close index table '" + filename + "': " +
                 closed.ToString());
  }
  std::string unhidden = UnhiddenFile(dirname_, micros_);
  LOG(INFO) << "Wrote all index files for " << filename << ", moving to "
            << unhidden;
  RETURN_IF_ERROR(Errno(rename(filename.c_str(), unhidden.c_str())), "rename");
  VLOG(1) << "Stored " << packets_ << " with " << ip4_.size() << " IP4 "
          << ip6_.size() << " IP6 " << proto_.size() << " protos "
          << port_.size() << " ports";
  return SUCCESS;
}

void Index::AddIP(leveldb::Slice ip, int64_t pos) {
  CHECK(ip.size() == 4 || ip.size() == 16);
  auto tree = ip.size() == 4 ? &ip4_ : &ip6_;
  auto finder = tree->find(ip);
  if (finder == tree->end()) {
    ip = ip_pieces_.Store(ip);
    (*tree)[ip].push_back(pos);
  } else {
    finder->second.push_back(pos);
  }
}
void Index::AddProtocol(uint8_t proto, int64_t pos) {
  auto finder = proto_.find(proto);
  if (finder == proto_.end()) {
    proto_[proto].push_back(pos);
  } else {
    finder->second.push_back(pos);
  }
}
void Index::AddPort(uint16_t port, int64_t pos) {
  auto finder = port_.find(port);
  if (finder == port_.end()) {
    port_[port].push_back(pos);
  } else {
    finder->second.push_back(pos);
  }
}

}  // namespace st
