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
#include <sys/ioctl.h>        // ioctl()

#include <memory>
#include <string>
#include <sstream>

#include "util.h"

namespace {

const int64_t kMinPollMillis = 10;

inline size_t Align(size_t v) {
  return (v + TPACKET_ALIGNMENT - 1) & ((~TPACKET_ALIGNMENT) - 1);
}

const int kNoFanout = -1;

}  // namespace

namespace st {

std::string Stats::String() const {
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
  releaser_ = NULL;
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
  std::swap(releaser_, b->releaser_);
  std::swap(releaser_arg_, b->releaser_arg_);
}

leveldb::Slice Block::Data() { return leveldb::Slice(start_, size_); }

void Block::Reset() { ResetTo(NULL, 0, NULL, NULL, NULL); }

bool Block::ReadyForUser() { return Status() & TP_STATUS_USER; }

void Block::ResetTo(char* data, size_t sz, std::mutex* mu, Block::Releaser r,
                    void* rarg) {
  Done();
  VLOG(2) << "New block " << reinterpret_cast<uintptr_t>(data);
  start_ = data;
  size_ = sz;
  mu_ = mu;
  releaser_ = r;
  releaser_arg_ = rarg;
  pkts_in_use_ = 0;
  if (mu_) {
    VLOG(3) << "BlockReset m" << int64_t(mu_) << " IN b" << int64_t(this);
    mu_->lock();
  }
  if (!start_) {
    return;
  }
  block_ = reinterpret_cast<struct tpacket_block_desc*>(start_);
  packet_ = reinterpret_cast<struct tpacket3_hdr*>(
      start_ + block_->hdr.bh1.offset_to_first_pkt);
}

void Block::Done() {
  if (block_ != NULL) {
    ReturnToKernel();
    block_ = NULL;
    start_ = NULL;
    releaser_ = NULL;
  }
  if (mu_ != NULL) {
    VLOG(3) << "BlockDone m" << int64_t(mu_) << " IN b" << int64_t(this);
    mu_->unlock();
    mu_ = NULL;
  }
}

static void LocalBlock_ReturnToKernel(struct tpacket_block_desc* block,
                                      void* ths) {
  VLOG(2) << "Returning to kernel: " << reinterpret_cast<uintptr_t>(block);
  block->hdr.bh1.block_status = TP_STATUS_KERNEL;
}

void Block::ReturnToKernel() { releaser_(block_, releaser_arg_); }

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

#ifdef TESTIMONY
TestimonyPackets::TestimonyPackets(testimony t) : t_(t) {}

TestimonyPackets::~TestimonyPackets() {
  CHECK_SUCCESS(NegErrno(testimony_close(t_)));
}

void TestimonyPackets::TReturnToKernel(struct tpacket_block_desc* block,
                                       void* ths) {
  TestimonyPackets* t = reinterpret_cast<TestimonyPackets*>(ths);
  CHECK_SUCCESS(NegErrno(testimony_return_block(t->t_, block)));
}

Error TestimonyPackets::NextBlock(Block* b, int poll_millis) {
  const struct tpacket_block_desc* block;
  CHECK_SUCCESS(NegErrno(testimony_get_block(t_, poll_millis, &block)));
  if (block == NULL) {
    return SUCCESS;
  }  // timeout
  Block local;
  local.ResetTo((char*)block, testimony_conn(t_)->block_size, NULL,
                &TestimonyPackets::TReturnToKernel, this);
  local.Swap(b);
  return SUCCESS;
}

Error TestimonyPackets::GetStats(Stats* stats) { return SUCCESS; }
#endif

PacketsV3::PacketsV3(PacketsV3::State* state) {
  state_.Swap(state);
  offset_ = state_.num_blocks - 1;
  block_mus_ = new std::mutex[state_.num_blocks];
}

Error PacketsV3::GetStats(Stats* stats) {
  struct tpacket_stats_v3 tpstats;
  socklen_t len = sizeof(tpstats);
  RETURN_IF_ERROR(Errno(getsockopt(state_.fd, SOL_PACKET, PACKET_STATISTICS,
                                   &tpstats, &len)),
                  "getsockopt PACKET_STATISTICS");
  stats_.drops += tpstats.tp_drops;
  *stats = stats_;
  return SUCCESS;
}

Error PacketsV3::Builder::Bind(const std::string& iface, Packets** out) {
  RETURN_IF_ERROR(BadState(), "Builder");

  unsigned int ifindex = if_nametoindex(iface.c_str());
  if (ifindex == 0) {
    return Errno();
  }
  if (promisc_) {
    VLOG(1) << "Setting promiscuous mode for " << iface;
    struct ifreq ifopts;
    memset(&ifopts, 0, sizeof(ifopts));
    strncpy(ifopts.ifr_name, iface.c_str(), IFNAMSIZ-1);
    RETURN_IF_ERROR(
        Errno(ioctl(state_.fd, SIOCGIFFLAGS, &ifopts)),
        "getting current interface flags");
    if (ifopts.ifr_flags & IFF_PROMISC) {
      VLOG(1) << "Interface " << iface << " already in promisc mode";
    } else {
      ifopts.ifr_flags |= IFF_PROMISC;
      RETURN_IF_ERROR(
          Errno(ioctl(state_.fd, SIOCSIFFLAGS, &ifopts)),
          "turning on promisc");
    }
  }

  struct sockaddr_ll ll;
  memset(&ll, 0, sizeof(ll));
  ll.sll_family = AF_PACKET;
  ll.sll_protocol = htons(ETH_P_ALL);
  ll.sll_ifindex = ifindex;
  RETURN_IF_ERROR(
      Errno(::bind(state_.fd, reinterpret_cast<struct sockaddr*>(&ll),
                   sizeof(ll))),
      "bind");
  if (fanout_ != kNoFanout) {
    RETURN_IF_ERROR(Errno(setsockopt(state_.fd, SOL_PACKET, PACKET_FANOUT,
                                     &fanout_, sizeof(fanout_))),
                    "setting fanout");
  }
  *out = new PacketsV3(&state_);
  return SUCCESS;
}

Error PacketsV3::Builder::SetFilter(const std::string& filter) {
  RETURN_IF_ERROR(BadState(), "Builder");

  int filter_size = filter.size();
  int filter_element_size = 4 + 2 + 2 + 8;
  if (filter_size % filter_element_size) {
    return ERROR("invalid filter length");
  }
  int num_structs = filter_size / filter_element_size;
  if (USHRT_MAX < num_structs) {
    return ERROR("invalid filter: too long");
  }
  struct sock_filter bpf_filter[num_structs];
  const char* data = filter.c_str();
  for (int i = 0; i < num_structs; i++) {
    if (4 != sscanf(data, "%4hx%2hhx%2hhx%8x", &bpf_filter[i].code,
                    &bpf_filter[i].jt, &bpf_filter[i].jf, &bpf_filter[i].k)) {
      return ERROR("invalid filter");
    }
    data += filter_element_size;
  }
  struct sock_fprog bpf = {(unsigned short int)num_structs, bpf_filter};
  RETURN_IF_ERROR(Errno(setsockopt(state_.fd, SOL_SOCKET, SO_ATTACH_FILTER,
                                   &bpf, sizeof(bpf))),
                  "so_attach_filter");
#ifdef SO_LOCK_FILTER
  int v = 1;
  // SO_LOCK_FILTER is available only on kernels >= 3.9, so ignore the
  // ENOPROTOOPT
  // error here. We use it to make sure that no one can mess with our socket's
  // filter, so not having it is not really a big concern.
  RETURN_IF_ERROR(
      Errno(setsockopt(state_.fd, SOL_SOCKET, SO_LOCK_FILTER, &v, sizeof(v)) ||
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
  return Errno(setsockopt(state_.fd, SOL_PACKET, PACKET_VERSION, &version,
                          sizeof(version)));
}

Error PacketsV3::Builder::SetFanout(uint16_t fanout_type, uint16_t fanout_id) {
  RETURN_IF_ERROR(BadState(), "Builder");
  // We can't actually set fanout until we bind, so just save it instead.
  VLOG(1) << "Setting fanout to type " << fanout_type << " ID " << fanout_id;
  fanout_ = fanout_type;
  fanout_ <<= 16;
  fanout_ |= fanout_id;
  return SUCCESS;
}

Error PacketsV3::Builder::SetPromisc(bool promisc) {
  promisc_ = promisc;
  return SUCCESS;
}

Error PacketsV3::Builder::SetRingOptions(void* options, socklen_t size) {
  return Errno(
      setsockopt(state_.fd, SOL_PACKET, PACKET_RX_RING, options, size));
}

Error PacketsV3::Builder::MMapRing() {
  state_.ring = reinterpret_cast<char*>(
      mmap(NULL, state_.block_size * state_.num_blocks, PROT_READ | PROT_WRITE,
           MAP_SHARED | MAP_LOCKED | MAP_NORESERVE, state_.fd, 0));
  if (state_.ring == MAP_FAILED) {
    return Errno();
  }
  return SUCCESS;
}

// socktype is SOCK_RAW or SOCK_DGRAM.
Error PacketsV3::Builder::CreateSocket(int socktype) {
  state_.fd = socket(AF_PACKET, socktype, 0);
  return Errno(state_.fd);
}

Error PacketsV3::PollForPacket(int poll_millis) {
  struct pollfd pfd;
  pfd.fd = state_.fd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  int64_t duration_micros = -GetCurrentTimeMicros();
  int ret = poll(&pfd, 1, poll_millis);
  Error out = Errno(ret);
  duration_micros += GetCurrentTimeMicros();
  SleepForMicroseconds(kMinPollMillis * kNumMicrosPerMilli - duration_micros);
  return out;
}

void PacketsV3::State::Swap(PacketsV3::State* s) {
  std::swap(fd, s->fd);
  std::swap(ring, s->ring);
  std::swap(num_blocks, s->num_blocks);
  std::swap(block_size, s->block_size);
}

PacketsV3::State::~State() {
  if (ring != NULL && ring != MAP_FAILED) {
    munmap(ring, block_size * num_blocks);
  }
  if (fd >= 0) {
    close(fd);
  }
}

PacketsV3::~PacketsV3() {
  pos_.Done();
  for (size_t i = 0; i < state_.num_blocks; i++) {
    // Wait for all blocks to be returned to kernel.
    VLOG(3) << "PacketsV3Destructor lock m" << int64_t(&block_mus_[i]);
    block_mus_[i].lock();
    block_mus_[i].unlock();
    VLOG(3) << "PacketsV3Destructor unlock m" << int64_t(&block_mus_[i]);
  }
  delete[] block_mus_;
}

PacketsV3::Builder::Builder() : fanout_(kNoFanout) {}

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

Error PacketsV3::NextBlock(Block* b, int poll_millis) {
  if (pos_.Empty()) {
    // If we're finished with the current block, move to the next block.
    offset_ = (offset_ + 1) % state_.num_blocks;
    // This constructor locks the passed-in mu on creation, so it'll
    // wait for that mu to be unlocked by the last user of this block.
    pos_.ResetTo(state_.ring + offset_ * state_.block_size, state_.block_size,
                 &block_mus_[offset_], &LocalBlock_ReturnToKernel, NULL);
  }
  if (!pos_.ReadyForUser()) {
    stats_.polls++;
    RETURN_IF_ERROR(PollForPacket(poll_millis), "polling for packet");
  }
  if (pos_.ReadyForUser()) {
    pos_.UpdateStats(&stats_);
    VLOG(3) << "PacketsV3NextBlock b" << int64_t(&pos_) << " INTO b"
            << int64_t(b);
    pos_.Swap(b);
  }
  return SUCCESS;
}

}  // namespace st
