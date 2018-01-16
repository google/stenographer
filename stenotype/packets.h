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

#ifdef TESTIMONY
#include <testimony.h>
#endif

#include "util.h"

namespace st {

// Information on a single packet in an AF_PACKET block.
struct Packet {
  leveldb::Slice data;  // Packet data as stored in the block.
  int64_t length;       // Actual length of full packet (could be > data.size())
  int64_t timestamp_nsecs;  // Timestamp packet was captured

  // Start of packet data relative to start of block.  Note this is the location
  // of the packet header info, not the start of the packet data itself.
  size_t offset_in_block;
};

struct Stats {
  Stats() : packets(0), blocks(0), polls(0), drops(0) {}
  std::string String() const;
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
  Block();           // Create an empty block, not referencing anything.
  virtual ~Block();  // Dereference block's memory, releasing it back to kernel.
  void Swap(Block* b);  // Swap references with another block.

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
#ifdef TESTIMONY
  friend class TestimonyPackets;
#endif
  typedef void (*Releaser)(struct tpacket_block_desc*, void*);
  void UpdateStats(Stats* stats);
  bool ReadyForUser();
  void ResetTo(char* data, size_t sz, std::mutex* mu, Releaser r, void* rarg);
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
  std::mutex* mu_;
  Releaser releaser_;
  void* releaser_arg_;

  DISALLOW_COPY_AND_ASSIGN(Block);
};

class Packets {
 public:
  Packets() {}
  // Tear down this AF_PACKET socket.
  virtual ~Packets() {}

  // Get the next available Block, blocking until it's available.  Should not be
  // used in conjunction with Next.  Note that there are a fixed number of
  // blocks in each Packets... if you grab all of them without releasing any,
  // you'll deadlock your system.
  //
  // This will block at least kMinPollMillis and at most poll_millis.
  virtual Error NextBlock(Block* b, int poll_millis) = 0;
  // Get all currently available statistics about operation so far.
  virtual Error GetStats(Stats* stats) = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(Packets);
};

#ifdef TESTIMONY
class TestimonyPackets : public Packets {
 public:
  TestimonyPackets(testimony t);
  virtual ~TestimonyPackets();
  virtual Error NextBlock(Block* b, int poll_millis);
  virtual Error GetStats(Stats* stats);

 private:
  static void TReturnToKernel(struct tpacket_block_desc*, void* ths);
  testimony t_;
};
#endif

// PacketsV3 wraps MMAP'd AF_PACKET TPACKET_V3 in a nice, easy(er) to use
// object.  Not safe for concurrent operation.
class PacketsV3 : public Packets {
 private:
  // State provides state common to PacketsV3 and PacketsV3::Builder.
  struct State {
    State() : fd(-1), ring(NULL), block_size(0), num_blocks(0) {}
    ~State();
    void Swap(State* s);
    int fd;             // file descriptor for AF_PACKET socket.
    char* ring;         // pointer to start of mmap'd region.
    size_t block_size;  // size of each block.
    size_t num_blocks;  // total number of blocks.
    const char* iface;  // Interface
  };

 public:
  // Tear down this AF_PACKET socket.
  virtual ~PacketsV3();

  // Get the next available Block, blocking until it's available.  Should not be
  // used in conjunction with Next.  Note that there are a fixed number of
  // blocks in each PacketsV3... if you grab all of them without releasing any,
  // you'll deadlock your system.
  //
  // This will block at least kMinPollMillis and at most poll_millis.
  virtual Error NextBlock(Block* b, int poll_millis);
  // Get all currently available statistics about operation so far.
  virtual Error GetStats(Stats* stats);

  // Builder allows users to build a PacketsV3 object.
  //
  // Building a PacketsV3 involves:
  //   PacketsV3::Builder builder;
  //   builder.SetUp(...);  // initial setup
  //   builder.X(...);  // optionally set filters, fanout, etc.
  //   PacketsV3* v3;
  //   builder.Bind("eth0", &v3);  // create the PacketsV3 and bind it.
  // Once this has been completed, 'v3' will be sniffing packets and good to go.
  // A single Builder instance may be used to create more than one PacketsV3...
  // its state is cleared after the Bind call, though, so a new set of
  // SetUp/.../Bind must be run.  Builder has no memory of the last thing it
  // built.
  class Builder {
   public:
    Builder();

    // SetUp must be called before any of the following methods.  It sets up the
    // initial socket and mmap'd ring.  Note: the socket is set up such that it
    // ignores packets until Bind is called.
    Error SetUp(int socktype, struct tpacket_req3 tp);

    // Tell this TPACKET_V3 instance to start fanning out packets among other
    // threads with the same type/id.
    Error SetFanout(uint16_t fanout_type, uint16_t fanout_id);

    // SetFilter sets a BPF filter on the socket.
    Error SetFilter(const std::string& filter);

    // Bind must be the final method called by Builder.  It binds the created
    // socket to the given interface and returns a PacketsV3 object to wrap it.
    Error Bind(const std::string& iface, Packets** out);

   private:
    Error BadState();
    Error SetVersion();
    Error SetRingOptions(void* options, socklen_t size);
    Error MMapRing();
    Error CreateSocket(int socktype);
    Error SetPromisc();
    Error DisablePromisc();

    // State contains the state the builder sets up.  This state will be passed
    // to the PacketsV3 object created by Bind.
    State state_;
    int fanout_;
  };

 private:
  PacketsV3(State* state);
  // This will block at least kMinPollMillis and at most poll_millis.
  Error PollForPacket(int poll_millis);

  State state_;
  int offset_;   // next block number to be processed.
  Block pos_;    // block currently being processed.
  Stats stats_;  // statistics on block processing so far.
  // Locks, one per block.  Block objects hold a lock to their memory region
  // during their lifetime, and release it on destruction.  This allows us to
  // correctly use the circular queue without overrunning if it gets full.
  std::mutex* block_mus_;

  DISALLOW_COPY_AND_ASSIGN(PacketsV3);
};

}  // namespace st

#endif  // EXPERIMENTAL_USERS_GCONNELL_AFPACKET_PACKETS_H_
