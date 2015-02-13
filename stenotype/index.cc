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

// kTypeEthernet is NOT a valid ETH_P_ type.  We use it to signify that the next
// layer to decode is an ethernet header.
const uint16_t kTypeEthernet = 0;
const uint32_t kMPLSBottomOfStack = 1 << 8;

void Index::Process(const Packet& p, int64_t block_offset) {
  packets_++;
  int64_t packet_offset = block_offset + p.offset_in_block;
  CHECK(packet_offset < (int64_t(1) << 32));
  const char* start = p.data.data();
  const char* limit = start + p.data.size();
  uint16_t type = kTypeEthernet;
  uint8_t protocol = 0;

// We use a goto loop within this switch statement to strip all pre-IP-header
// layers off of the given packet.
pre_ip_encapsulation:
  switch (type) {
    case kTypeEthernet: {
      if (start + sizeof(struct ethhdr) > limit) {
        return;
      }
      auto eth = reinterpret_cast<const struct ethhdr*>(start);
      start += sizeof(struct ethhdr);
      type = ntohs(eth->h_proto);
      goto pre_ip_encapsulation;
    }
    case ETH_P_8021Q:
    case ETH_P_8021AD:
    case ETH_P_QINQ1:
    case ETH_P_QINQ2:
    case ETH_P_QINQ3: {
      if (start + 4 > limit) {
        return;
      }
      AddVLAN(ntohs(*reinterpret_cast<const uint16_t*>(start)) & 0x0FFF,
              packet_offset);
      type = ntohs(*reinterpret_cast<const uint16_t*>(start + 2));
      start += 4;
      goto pre_ip_encapsulation;
    }
    case ETH_P_MPLS_UC:
    case ETH_P_MPLS_MC: {
      uint32_t mpls_header = 0;
      do {
        // We check for 5 bytes, because we need to parse the first nibble after
        // the MPLS header to figure out the next layer type.
        if (start + 5 > limit) {
          return;
        }
        mpls_header = ntohl(*reinterpret_cast<const uint32_t*>(start));
        AddMPLS(mpls_header >> 12, packet_offset);
        start += 4;
      } while (!(mpls_header & kMPLSBottomOfStack));
      // Use the first nibble after the last MPLS layer to determine the
      // underlying packet type.
      switch (start[0] >> 4) {
        case 0:  // RFC4385
          type = kTypeEthernet;
          start += 4;  // Skip over PW ethernet control word.
          break;
        case 4:
          type = ETH_P_IP;
          break;
        case 6:
          type = ETH_P_IPV6;
          break;
        default:
          return;
      }
      goto pre_ip_encapsulation;
    }

    // All of the above use the pre_ip_encapsulation loop.
    // All of the below do not.

    case ETH_P_IP: {
      if (start + sizeof(struct iphdr) > limit) {
        return;
      }
      auto ip4 = reinterpret_cast<const struct iphdr*>(start);
      AddIPv4(ntohl(ip4->saddr), packet_offset);
      AddIPv4(ntohl(ip4->daddr), packet_offset);
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
      AddIPv6(leveldb::Slice(reinterpret_cast<const char*>(&ip6->ip6_src), 16),
              packet_offset);
      AddIPv6(leveldb::Slice(reinterpret_cast<const char*>(&ip6->ip6_dst), 16),
              packet_offset);

    // Here, we use another goto loop to strip off all IPv6 extensions.
    ip6_extensions:
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
          goto ip6_extensions;
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

// ValueFromVector returns a leveldb slice to act as the value in an index,
// converting the passed-in vector into that slice.
//
// This function destructively modifies the passed-in vector, and the return
// value references that vector's memory space.  This function cannot be called
// on the same vector more than once, and the returned slice cannot be used if
// the passed-in vector is modified after this function returns.
leveldb::Slice ValueFromVector(std::vector<uint32_t>& vec) {
  CHECK(vec.size() > 0);
  size_t size = 1;
  uint32_t last = vec[0];
  vec[0] = htonl(last);
  for (size_t i = 1; i < vec.size(); i++) {
    if (vec[i] != last) {
      last = vec[i];
      vec[size] = htonl(last);  // convert to network order.
      size++;
    }
  }
  return leveldb::Slice(reinterpret_cast<const char*>(vec.data()), size * 4);
}

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

void WriteToIndex(char first, const char* start, int size,
                  std::vector<uint32_t>& val, leveldb::TableBuilder* ss) {
  char buf[1 +   // First byte is type of index (ip4, ip6, proto, etc)
           16];  // Last 1-16 bytes are type-specific index values.
  CHECK(size <= 16);
  buf[0] = first;
  memcpy(buf + 1, start, size);
  ss->Add(leveldb::Slice(buf, size + 1), ValueFromVector(val));
}

// Should be incremented for backwards-incompatible changes.
const uint16_t kIndexVersionNumberMajor = 2;
// Should be incremented for backwards-compatible changes.
const uint16_t kIndexVersionNumberMinor = 0;

const char kIndexVersion = 0;
const char kIndexProtocol = 1;
const char kIndexPort = 2;
const char kIndexVLAN = 3;
const char kIndexIPv4 = 4;
const char kIndexMPLS = 5;
const char kIndexIPv6 = 6;

}  // namespace

Error Index::Flush() {
  leveldb::WritableFile* file;
  std::string filename = HiddenFile(dirname_, micros_);
  auto status = leveldb::Env::Default()->NewWritableFile(filename, &file);
  if (!status.ok()) {
    return ERROR("could not open '" + filename + "': " + status.ToString());
  }
  std::unique_ptr<leveldb::WritableFile> cleaner(file);

  RETURN_IF_ERROR(WriteTo(file), "writing index " + filename);

  std::string unhidden = UnhiddenFile(dirname_, micros_);
  LOG(INFO) << "Wrote all index files for " << filename << ", moving to "
            << unhidden;
  RETURN_IF_ERROR(Errno(rename(filename.c_str(), unhidden.c_str())), "rename");
  LOG(V1) << "Stored " << packets_ << " with " << ip4_.size() << " IP4 "
          << ip6_.size() << " IP6 " << proto_.size() << " protos "
          << port_.size() << " ports " << vlan_.size() << " vlan "
          << mpls_.size() << " mpls";
  return SUCCESS;
}

Error Index::WriteTo(leveldb::WritableFile* file) {
  leveldb::Options options;
  options.compression = leveldb::kNoCompression;
  leveldb::TableBuilder index_ss(options, file);

  // The first entry we write is the version number that defines
  // the format for this file.
  char versionKeyBuf[1] = {0};
  char versionBuf[8];
  *reinterpret_cast<uint32_t*>(versionBuf) = htonl(kIndexVersionNumberMajor);
  *reinterpret_cast<uint32_t*>(versionBuf + 4) =
      htonl(kIndexVersionNumberMinor);
  index_ss.Add(leveldb::Slice(versionKeyBuf, 1), leveldb::Slice(versionBuf, 8));

#define WRITE_TO_INDEX(name, convert, indextype, size)                    \
  do {                                                                    \
    for (auto iter : name##_) {                                           \
      auto name = convert(iter.first);                                    \
      WriteToIndex(indextype, reinterpret_cast<const char*>(&name), size, \
                   iter.second, &index_ss);                               \
    }                                                                     \
  } while (0)

  WRITE_TO_INDEX(proto, , kIndexProtocol, 1);
  WRITE_TO_INDEX(port, htons, kIndexPort, 2);
  WRITE_TO_INDEX(vlan, htons, kIndexVLAN, 2);
  WRITE_TO_INDEX(ip4, htonl, kIndexIPv4, 4);
  WRITE_TO_INDEX(mpls, htonl, kIndexMPLS, 4);

#undef WRITE_TO_INDEX

  for (auto iter : ip6_) {
    auto ip6 = iter.first.data();
    WriteToIndex(kIndexIPv6, ip6, 16, iter.second, &index_ss);
  }

  auto finished = index_ss.Finish();
  if (!finished.ok()) {
    return ERROR("could not finish writing index table: " +
                 finished.ToString());
  }
  auto closed = file->Close();
  if (!closed.ok()) {
    return ERROR("could not close index table: " + closed.ToString());
  }
  return SUCCESS;
}

void Index::AddIPv6(leveldb::Slice ip, uint32_t pos) {
  CHECK(ip.size() == 16);
  auto finder = ip6_.find(ip);
  if (finder == ip6_.end()) {
    ip = ip_pieces_.Store(ip);
    ip6_[ip].push_back(pos);
  } else {
    finder->second.push_back(pos);
  }
}

#define ADD_TO_INDEX(name, pos)   \
  do {                            \
    name##_[name].push_back(pos); \
  } while (0)

void Index::AddProtocol(uint8_t proto, uint32_t pos) {
  ADD_TO_INDEX(proto, pos);
}
void Index::AddPort(uint16_t port, uint32_t pos) { ADD_TO_INDEX(port, pos); }
void Index::AddVLAN(uint16_t vlan, uint32_t pos) { ADD_TO_INDEX(vlan, pos); }
void Index::AddMPLS(uint32_t mpls, uint32_t pos) { ADD_TO_INDEX(mpls, pos); }
void Index::AddIPv4(uint32_t ip4, uint32_t pos) { ADD_TO_INDEX(ip4, pos); }

#undef ADD_TO_INDEX

}  // namespace st
