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

#include "packets.h"

#include <climits>            // USHRT_MAX
#include <errno.h>            // errno, ENOPROTOOPT
#include <linux/if_ether.h>   // ETH_P_ALL
#include <linux/if_packet.h>  // AF_PACKET, sockaddr_ll
#include <linux/filter.h>     // SO_ATTACH_FILTER, SO_LOCK_FILTER
#include <net/if.h>           // if_nametoindex()
#include <netinet/in.h>       // htons()
#include <poll.h>             // poll()
#include <string.h>           // strerror()
#include <sys/mman.h>         // mmap(), munmap()
#include <sys/socket.h>       // socket()
#include <unistd.h>           // close(), getpid()

#include <memory>
#include <string>
#include <sstream>

#include "util.h"

namespace {

const int64_t kMinPollMillis = 10;

inline size_t Align(size_t v) {
  return (v + TPACKET_ALIGNMENT - 1) & ((~TPACKET_ALIGNMENT) - 1);
}

}  // namespace

namespace st {

string Stats::String() const {
  std::stringstream out;
  out << "packets=" << packets << " blocks=" << blocks << " polls=" << polls
      << " drops=" << drops
      << " drop%=" << drops* double(100.0) / (drops + packets);
  return out.str();
}

void Block::UpdateStats(Stats* stats) {
  if (start_) {
    stats->packets += block_->hdr.bh1.num_pkts;
    stats->blocks++;
  }
}
Block::Block() {
  start_ = NULL;
  block_ = NULL;
  packet_ = NULL;
  mu_ = NULL;
  size_ = 0;
  pkts_in_use_ = 0;
}
Block::~Block() { Done(); }
void Block::Swap(Block* b) {
  if (b == this) {
    return;
  }
  std::swap(start_, b->start_);
  std::swap(block_, b->block_);
  std::swap(packet_, b->packet_);
  std::swap(mu_, b->mu_);
  std::swap(size_, b->size_);
  std::swap(pkts_in_use_, b->pkts_in_use_);
}

leveldb::Slice Block::Data() { return leveldb::Slice(start_, size_); }

void Block::Reset() { ResetTo(NULL, 0, NULL); }

bool Block::ReadyForUser() { return Status() & TP_STATUS_USER; }

void Block::ResetTo(char* data, size_t sz, Mutex* mu) {
  Done();
  LOG(V2) << "New block " << reinterpret_cast<uintptr_t>(data);
  start_ = data;
  size_ = sz;
  mu_ = mu;
  pkts_in_use_ = 0;
  if (mu_) {
    mu_->Lock();
  }
  if (!start_) {
    return;
  }
  block_ = reinterpret_cast<struct tpacket_block_desc*>(start_);
  packet_ = reinterpret_cast<struct tpacket3_hdr*>(
      start_ + block_->hdr.bh1.offset_to_first_pkt);
}

void Block::Done() {
  if (start_ != NULL) {
    ReturnToKernel();
    start_ = NULL;
  }
  if (mu_ != NULL) {
    mu_->Unlock();
    mu_ = NULL;
  }
}

void Block::ReturnToKernel() {
  LOG(V2) << "Returning to kernel: " << reinterpret_cast<uintptr_t>(block_);
  block_->hdr.bh1.block_status = TP_STATUS_KERNEL;
}

void Block::MoveToNext() {
  pkts_in_use_++;
  char* next = reinterpret_cast<char*>(packet_);
  if (packet_->tp_next_offset != 0) {
    next += packet_->tp_next_offset;
  } else {
    next += Align(packet_->tp_snaplen + packet_->tp_mac);
  }
  packet_ = reinterpret_cast<struct tpacket3_hdr*>(next);
}

int Block::Status() { return block_->hdr.bh1.block_status; }
int64_t Block::TimeNSecs() {
  return packet_->tp_sec * 1000000000 + packet_->tp_nsec;
}
leveldb::Slice Block::PacketData() {
  return leveldb::Slice(reinterpret_cast<char*>(packet_) + packet_->tp_mac,
                        packet_->tp_snaplen);
}
size_t Block::Length() { return packet_->tp_len; }
size_t Block::PacketOffset() {
  return reinterpret_cast<char*>(packet_) - start_;
}

bool Block::Next(Packet* p) {
  if (start_ == NULL || pkts_in_use_ >= block_->hdr.bh1.num_pkts) {
    return false;
  }
  p->data = PacketData();
  p->length = Length();
  p->timestamp_nsecs = TimeNSecs();
  p->offset_in_block = PacketOffset();
  MoveToNext();
  return true;
}

PacketsV3::PacketsV3(PacketsV3::State* state) {
  state_.Swap(state);
  offset_ = state_.num_blocks - 1;
  block_mus_ = new Mutex[state_.num_blocks];
}

Error PacketsV3::GetStats(Stats* stats) {
  struct tpacket_stats_v3 tpstats;
  socklen_t len = sizeof(tpstats);
  RETURN_IF_ERROR(Errno(0 <= getsockopt(state_.fd, SOL_PACKET,
                                        PACKET_STATISTICS, &tpstats, &len)),
                  "getsockopt PACKET_STATISTICS");
  stats_.drops += tpstats.tp_drops;
  *stats = stats_;
  return SUCCESS;
}

Error PacketsV3::Builder::Bind(const string& iface, PacketsV3** out) {
  RETURN_IF_ERROR(BadState(), "Builder");

  unsigned int ifindex = if_nametoindex(iface.c_str());
  RETURN_IF_ERROR(Errno(ifindex != 0), "if_nametoindex");
  struct sockaddr_ll ll;
  memset(&ll, 0, sizeof(ll));
  ll.sll_family = AF_PACKET;
  ll.sll_protocol = htons(ETH_P_ALL);
  ll.sll_ifindex = ifindex;
  RETURN_IF_ERROR(
      Errno(0 <= ::bind(state_.fd, reinterpret_cast<struct sockaddr*>(&ll),
                        sizeof(ll))),
      "bind");
  *out = new PacketsV3(&state_);
  return SUCCESS;
}

Error PacketsV3::Builder::SetFilter(const string& filter) {
  RETURN_IF_ERROR(BadState(), "Builder");

  if (filter.empty()) return SUCCESS;

  int filter_size = filter.size();
  int filter_element_size = 4 + 2 + 2 + 8;
  RETURN_IF_ERROR(Errno(0 == filter_size % filter_element_size),
                  "invalid filter length");
  int num_structs = filter_size / filter_element_size;
  RETURN_IF_ERROR(Errno(USHRT_MAX >= num_structs), "invalid filter: too long");
  struct sock_filter bpf_filter[num_structs];
  const char* data = filter.c_str();
  for (int i = 0; i < num_structs; i++) {
    RETURN_IF_ERROR(Errno(4 == sscanf(data, "%4hx%2hhx%2hhx%8x",
                                      &bpf_filter[i].code, &bpf_filter[i].jt,
                                      &bpf_filter[i].jf, &bpf_filter[i].k)),
                    "invalid filter");
    data += filter_element_size;
  }
  RETURN_IF_ERROR(Errno(0 == errno), "failure while parsing filter");

  struct sock_fprog bpf = {(unsigned short int)num_structs, bpf_filter};
  RETURN_IF_ERROR(Errno(0 == setsockopt(state_.fd, SOL_SOCKET, SO_ATTACH_FILTER,
                                        &bpf, sizeof(bpf))),
                  "so_attach_filter");
#ifdef SO_LOCK_FILTER
  int v = 1;
  // SO_LOCK_FILTER is available only on kernels >= 3.9, so ignore the
  // ENOPROTOOPT
  // error here. We use it to make sure that no one can mess with our socket's
  // filter, so not having it is not really a big concern.
  RETURN_IF_ERROR(Errno(0 == setsockopt(state_.fd, SOL_SOCKET, SO_LOCK_FILTER,
                                        &v, sizeof(v)) ||
                        errno == ENOPROTOOPT),
                  "so_lock_filter");
  errno = 0;
#endif
  return SUCCESS;
}

Error PacketsV3::Builder::BadState() {
  if (state_.fd < 0) {
    return ERROR(
        "builder in bad state... SetUp not called or Bind already called");
  }
  return SUCCESS;
}

Error PacketsV3::Builder::SetVersion() {
  int version = TPACKET_V3;
  return Errno(0 <= setsockopt(state_.fd, SOL_PACKET, PACKET_VERSION, &version,
                               sizeof(version)));
}

Error PacketsV3::Builder::SetFanout(uint16_t fanout_type, uint16_t fanout_id) {
  RETURN_IF_ERROR(BadState(), "Builder");
  LOG(V1) << "Setting fanout to type " << fanout_type << " ID " << fanout_id;
  uint32_t fanout = fanout_type;
  fanout <<= 16;
  fanout |= fanout_id;
  RETURN_IF_ERROR(Errno(0 <= setsockopt(state_.fd, SOL_PACKET, PACKET_FANOUT,
                                        &fanout, sizeof(fanout))),
                  "setting fanout options");
  return SUCCESS;
}

Error PacketsV3::Builder::SetRingOptions(void* options, socklen_t size) {
  RETURN_IF_ERROR(Errno(0 <= setsockopt(state_.fd, SOL_PACKET, PACKET_RX_RING,
                                        options, size)),
                  "setting socket ring options");
  return SUCCESS;
}

Error PacketsV3::Builder::MMapRing() {
  state_.ring = reinterpret_cast<char*>(
      mmap(NULL, state_.block_size * state_.num_blocks, PROT_READ | PROT_WRITE,
           MAP_SHARED | MAP_LOCKED | MAP_NORESERVE, state_.fd, 0));
  RETURN_IF_ERROR(Errno(errno == 0), "mmap-ing ring");
  return SUCCESS;
}

// socktype is SOCK_RAW or SOCK_DGRAM.
Error PacketsV3::Builder::CreateSocket(int socktype) {
  state_.fd = socket(AF_PACKET, socktype, 0);
  RETURN_IF_ERROR(Errno(state_.fd >= 0), "creating socket");
  return SUCCESS;
}

Error PacketsV3::PollForPacket() {
  struct pollfd pfd;
  pfd.fd = state_.fd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  int64_t duration_micros = -GetCurrentTimeMicros();
  int ret = poll(&pfd, 1, -1);
  duration_micros += GetCurrentTimeMicros();
  SleepForMicroseconds(kMinPollMillis * kNumMicrosPerMilli - duration_micros);
  return Errno(ret >= 0);
}

void PacketsV3::State::Swap(PacketsV3::State* s) {
  std::swap(fd, s->fd);
  std::swap(ring, s->ring);
  std::swap(num_blocks, s->num_blocks);
  std::swap(block_size, s->block_size);
}

PacketsV3::State::~State() {
  if (ring) {
    munmap(ring, block_size * num_blocks);
  }
  if (fd >= 0) {
    close(fd);
  }
}

PacketsV3::~PacketsV3() {
  for (size_t i = 0; i < state_.num_blocks; i++) {
    // Wait for all blocks to be returned to kernel.
    block_mus_[i].Lock();
    block_mus_[i].Unlock();
  }
  delete[] block_mus_;
}

PacketsV3::Builder::Builder() {}

Error PacketsV3::Builder::SetUp(int socktype, struct tpacket_req3 tp) {
  if (tp.tp_block_size % getpagesize() != 0) {
    return ERROR("block size not divisible by page size");
  }
  if (tp.tp_block_size % tp.tp_frame_size != 0) {
    return ERROR("block size not divisible by frame size");
  }
  if (tp.tp_block_nr < 1) {
    return ERROR("block number must be > 1");
  }
  unsigned int frames_per_block = tp.tp_block_size / tp.tp_frame_size;
  unsigned int total_frames = frames_per_block * tp.tp_block_nr;
  if (tp.tp_frame_nr == 0) {
    tp.tp_frame_nr = total_frames;
  } else if (tp.tp_frame_nr != total_frames) {
    return ERROR("num frames does not match");
  }
  state_.block_size = tp.tp_block_size;
  state_.num_blocks = tp.tp_block_nr;
  RETURN_IF_ERROR(CreateSocket(socktype), "CreateSocket");
  RETURN_IF_ERROR(SetVersion(), "SetVersion");
  RETURN_IF_ERROR(SetRingOptions(&tp, sizeof(tp)), "SetRingOptions");
  RETURN_IF_ERROR(MMapRing(), "MMapRing");
  return SUCCESS;
}

Error PacketsV3::NextBlock(Block* b, bool poll_once) {
  if (pos_.Empty()) {
    // If we're finished with the current block, move to the next block.
    offset_ = (offset_ + 1) % state_.num_blocks;
    // This constructor locks the passed-in mu on creation, so it'll
    // wait for that mu to be unlocked by the last user of this block.
    pos_.ResetTo(state_.ring + offset_ * state_.block_size, state_.block_size,
                 &block_mus_[offset_]);
  }
  while (!pos_.ReadyForUser()) {
    stats_.polls++;
    RETURN_IF_ERROR(PollForPacket(), "polling for packet");
    if (poll_once) {
      break;
    }
  }
  if (pos_.ReadyForUser()) {
    pos_.UpdateStats(&stats_);
    pos_.Swap(b);
  }
  return SUCCESS;
}

Error PacketsV3::Next(Packet* p) {
  while (true) {
    if (pos_.Next(p)) {
      return SUCCESS;
    }
    RETURN_IF_ERROR(NextBlock(&pos_, false), "next block");
  }
}

}  // namespace st
