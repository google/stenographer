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

#ifndef EXPERIMENTAL_USERS_GCONNELL_AFPACKET_PACKETS_H_
#define EXPERIMENTAL_USERS_GCONNELL_AFPACKET_PACKETS_H_

#include <stddef.h>
#include <linux/if_packet.h>
#include <sys/socket.h>  // socklen_t

#include <memory>
#include <string>

#include <leveldb/slice.h>

#include "util.h"

namespace st {

class Mutex;

// Information on a single packet in an AF_PACKET block.
struct Packet {
  leveldb::Slice data;  // Packet data as stored in the block.
  int64_t length;  // Actual length of full packet (could be > data.size())
  int64_t timestamp_nsecs;  // Timestamp packet was captured

  // Start of packet data relative to start of block.  Note this is the location
  // of the packet header info, not the start of the packet data itself.
  size_t offset_in_block;
};

struct Stats {
  Stats() : packets(0), blocks(0), polls(0), drops(0) {}
  string String() const;
  int64_t packets;
  int64_t blocks;
  int64_t polls;
  int64_t drops;
};

// AF_PACKET (TPACKET_V3) gives us packets in memory blocks, where each block
// contains a linked list of packets in order.  This object wraps an individual
// block, and allows for things like iterating over all packets inside it, etc.
//
// A Block acts as a reference to its underlying memory region, and maintains a
// lock on that region, disallowing the kernel from reusing it.  Resetting or
// destructing the block object will release that lock, allowing the kernel to
// reuse the space in its ring buffer.
class Block {
 public:
  Block();  // Create an empty block, not referencing anything.
  virtual ~Block();  // Dereference block's memory, releasing it back to kernel.
  void Swap(Block *b);  // Swap references with another block.

  // Get the next packet in this block.  Returns OK on success, CANCELLED if
  // we've reached the end of all packets.
  bool Next(Packet* p);

  // Returns the underlying memory of the entire block.
  leveldb::Slice Data();

  // Reset the block, releasing it back to the kernel.
  void Reset();

  bool Empty() { return start_ == NULL; }

 private:
  friend class PacketsV3;
  void UpdateStats(Stats* stats);
  bool ReadyForUser();
  void ResetTo(char* data, size_t sz, Mutex* mu);
  void Done();
  void ReturnToKernel();
  void MoveToNext();
  int Status();
  int64_t TimeNSecs();
  leveldb::Slice PacketData();
  size_t Length();
  size_t PacketOffset();

  char* start_;
  size_t size_;
  struct tpacket_block_desc* block_;
  struct tpacket3_hdr* packet_;
  uint32_t pkts_in_use_;
  Mutex* mu_;

  DISALLOW_COPY_AND_ASSIGN(Block);
};

// PacketsV3 wraps MMAP'd AF_PACKET TPACKET_V3 in a nice, easy(er) to use
// object.  Not safe for concurrent operation.
class PacketsV3 {
 public:
  // Create a new PacketsV3 using the given options, socktype (SOCK_DGRAM or
  // SOCK_RAW), and bind it to the given interface.
  static Error V3(
      struct tpacket_req3 options, int socktype,
      const string& iface, PacketsV3** out);
  // Tear down this AF_PACKET socket.
  virtual ~PacketsV3();

  // Get the next available packet.  This function should not be used in
  // conjunction with NextBlock.  Blocks until packet is available.
  Error Next(Packet* p);
  // Get the next available Block, blocking until it's available.  Should not be
  // used in conjunction with Next.  Note that there are a fixed number of
  // blocks in each PacketsV3... if you grab all of them without releasing any,
  // you'll deadlock your system.
  //
  // If 'block' is true, blocks until a new block is available.  Otherwise, may
  // return immediately without a new block.  In that case, will not change *b
  // but will return SUCCESS.
  Error NextBlock(Block* b, bool block);
  // Get all currently available statistics about operation so far.
  Error GetStats(Stats* stats);

  // Tell this TPACKET_V3 instance to start fanning out packets among other
  // threads with the same type/id.
  Error SetFanout(uint16_t fanout_type, uint16_t fanout_id);

 private:
  PacketsV3(size_t num_blocks, size_t block_size);

  int fd_;  // file descriptor for AF_PACKET socket.
  char* ring_;  // pointer to start of mmap'd region.
  int offset_;  // next block number to be processed.
  size_t block_size_;  // size of each block.
  size_t num_blocks_;  // total number of blocks.
  Block pos_;  // block currently being processed.
  Stats stats_;  // statistics on block processing so far.
  // Locks, one per block.  Block objects hold a lock to their memory region
  // during their lifetime, and release it on destruction.  This allows us to
  // correctly use the circular queue without overrunning if it gets full.
  Mutex* block_mus_;

  Error Bind(const string& iface);
  Error SetVersion();
  Error SetRingOptions(void* options, socklen_t size);
  Error MMapRing();
  Error DrainSocket();
  Error CreateSocket(int socktype);
  Error PollForPacket();

  DISALLOW_COPY_AND_ASSIGN(PacketsV3);
};

}  // namespace st

#endif  // EXPERIMENTAL_USERS_GCONNELL_AFPACKET_PACKETS_H_
