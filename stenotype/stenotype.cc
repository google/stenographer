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

/***** stenotype *****
 *
 * stenotype is a mechanism for quickly dumping raw packets to disk.  It aims to
 * have a simple interface (no file rotation:  that's left as an exercise for
 * the reader) while being very powerful.
 *
 * stenotype uses a NIC->disk pipeline specifically designed to provide as fast
 * an output to disk as possible while just using the kernel's built-in
 *  mechanisms.
 *
 * 1) NIC -> RAM
 * stenotype uses MMAP'd AF_PACKET with 1MB blocks and a high timeout to offload
 * writing packets and deciding their layout to the kernel.  The kernel packs
 * all the packets it can into 1MB, then lets the userspace process know there's
 * a block available in the MMAP'd ring buffer.  Nicely, it guarantees no
 * overruns (packets crossing the 1MB boundary) and good alignment to memory
 * pages.
 *
 * 2) RAM -> Disk
 * Since the kernel already gave us a single 1MB block of packets that's nicely
 * aligned, we can O_DIRECT write it straight to disk.  This avoids any
 * additional copying or kernel buffering.  To keep sequential reads going
 * strong, we do all disk IO asynchronously via io_submit (which works
 * specifically for O_DIRECT files... joy!).  Since the data is being written to
 * disk asynchronously, we  use the time it's writing to disk to do our own
 * in-memory processing and indexing.
 *
 * There are N (flag-specified) async IO operations available... once we've used
 * up all N, we block on a used one finishing, then reuse it.
 * The whole pipeline consists of:
 *   - kernel gives userspace a 1MB block of packets
 *   - userspace iterates over packets in block, updates any indexes
 *   - userspace starts async IO operation to write block to disk
 *   - after N async IO operations are submitted, we synchronously wait for the
 *     least recent one to finish.
 *   - when an async IO operation finishes, we release the 1MB block back to the
 *     kernel to write more packets.
 */

#include <errno.h>            // errno
#include <fcntl.h>            // O_*
#include <grp.h>              // getgrnam()
#include <linux/if_packet.h>  // AF_PACKET, sockaddr_ll
#include <poll.h>             // POLLIN
#include <pthread.h>          // pthread_sigmask()
#include <pwd.h>              // getpwnam()
#include <sched.h>            // sched_setaffinity()
#include <seccomp.h>          // scmp_filter_ctx, seccomp_*(), SCMP_*
#include <signal.h>           // sigaction(), SIGINT, SIGTERM
#include <string.h>           // strerror()
#include <sys/prctl.h>        // prctl(), PR_SET_*
#include <sys/resource.h>     // setpriority(), PRIO_PROCESS
#include <sys/socket.h>       // socket()
#include <sys/syscall.h>      // syscall(), SYS_gettid
#include <unistd.h>           // setuid(), setgid()

#include <string>
#include <sstream>
#include <thread>

// Due to some weird interactions with <argp.h>, <string>, and --std=c++0x, this
// header MUST be included AFTER <string>.
#include <argp.h>  // argp_parse()

#include "aio.h"
#include "index.h"
#include "packets.h"
#include "util.h"

namespace {

std::string flag_iface = "eth0";
std::string flag_filter = "";
std::string flag_dir = "";
int64_t flag_count = -1;
int32_t flag_blocks = 2048;
int32_t flag_aiops = 128;
int64_t flag_filesize_mb = 4 << 10;
int32_t flag_threads = 1;
int64_t flag_fileage_sec = 60;
uint16_t flag_fanout_type =
// Use rollover as the default if it's available.
#ifdef PACKET_FANOUT_FLAG_ROLLOVER
    PACKET_FANOUT_LB | PACKET_FANOUT_FLAG_ROLLOVER;
#else
    PACKET_FANOUT_LB;
#endif
uint16_t flag_fanout_id = 0;
std::string flag_uid;
std::string flag_gid;
bool flag_index = true;
std::string flag_seccomp = "kill";
int flag_index_nicelevel = 0;
int flag_preallocate_file_mb = 0;

int ParseOptions(int key, char* arg, struct argp_state* state) {
  switch (key) {
    case 'v':
      st::logging_verbose_level++;
      break;
    case 'q':
      st::logging_verbose_level--;
      break;
    case 300:
      flag_iface = arg;
      break;
    case 301:
      flag_dir = arg;
      break;
    case 302:
      flag_count = atoi(arg);
      break;
    case 303:
      flag_blocks = atoi(arg);
      break;
    case 304:
      flag_aiops = atoi(arg);
      break;
    case 305:
      flag_filesize_mb = atoi(arg);
      break;
    case 306:
      flag_threads = atoi(arg);
      break;
    case 307:
      flag_fileage_sec = atoi(arg);
      break;
    case 308:
      flag_fanout_type = atoi(arg);
      break;
    case 309:
      flag_fanout_id = atoi(arg);
      break;
    case 310:
      flag_uid = arg;
      break;
    case 311:
      flag_gid = arg;
      break;
    case 312:
      flag_index = false;
      break;
    case 313:
      flag_index_nicelevel = atoi(arg);
      break;
    case 314:
      flag_filter = arg;
      break;
    case 315:
      flag_seccomp = arg;
      break;
    case 316:
      flag_preallocate_file_mb = atoi(arg);
      break;
  }
  return 0;
}

void ParseOptions(int argc, char** argv) {
  const char* s = "STRING";
  const char* n = "NUM";
  struct argp_option options[] = {
      {0, 'v', 0, 0, "Verbose logging, may be given multiple times"},
      {0, 'q', 0, 0, "Quiet logging.  Each -q counteracts one -v"},
      {"iface", 300, s, 0, "Interface to read packets from"},
      {"dir", 301, s, 0, "Directory to store packet files in"},
      {"count", 302, n, 0,
       "Total number of packets to read, -1 to read forever"},
      {"blocks", 303, n, 0, "Total number of blocks to use, each is 1MB"},
      {"aiops", 304, n, 0, "Max number of async IO operations"},
      {"filesize_mb", 305, n, 0, "Max file size in MB before file is rotated"},
      {"threads", 306, n, 0, "Number of parallel threads to read packets with"},
      {"fileage_sec", 307, n, 0, "Files older than this many secs are rotated"},
      {"fanout_type", 308, n, 0, "TPACKET_V3 fanout type to fanout packets"},
      {"fanout_id", 309, n, 0, "If fanning out across processes, set this"},
      {"uid", 310, n, 0, "Drop privileges to this user"},
      {"gid", 311, n, 0, "Drop privileges to this group"},
      {"no_index", 312, 0, 0, "Do not compute or write indexes"},
      {"index_nicelevel", 313, n, 0, "Nice level of indexing threads"},
      {"filter", 314, s, 0,
       "BPF compiled filter used to filter which packets "
       "will be captured. This has to be a compiled BPF in hexadecimal, which "
       "can be obtained from a human readable filter expression using the "
       "provided compile_bpf.sh script."},
      {"seccomp", 315, s, 0, "Seccomp style, one of 'none', 'trace', 'kill'."},
      {"preallocate_file_mb", 316, n, 0,
       "When creating new files, preallocate to this many MB"},
      {0}, };
  struct argp argp = {options, &ParseOptions};
  argp_parse(&argp, argc, argv, 0, 0, 0);
}

}  // namespace

namespace st {

// These two synchronization mechanisms are used to coordinate when to
// chroot/chuid so it's after when the threads create their sockets but before
// they start writing files.
Notification privileges_dropped;
Notification main_complete;
Barrier* sockets_created;

void DropPrivileges() {
  LOG(INFO) << "Dropping privileges";
  if (getgid() == 0 || flag_gid != "") {
    if (flag_gid == "") {
      flag_gid = "nobody";
    }
    LOG(INFO) << "Dropping priviledges from " << getgid() << " to GID "
              << flag_gid;
    auto group = getgrnam(flag_gid.c_str());
    CHECK(group != NULL) << "Unable to get info for group " << flag_gid;
    CHECK_SUCCESS(Errno(setgid(group->gr_gid)));
  } else {
    LOG(V1) << "Staying with GID=" << getgid();
  }
  if (getuid() == 0 || flag_uid != "") {
    if (flag_uid == "") {
      flag_uid = "nobody";
    }
    LOG(INFO) << "Dropping priviledges from " << getuid() << " to UID "
              << flag_uid;
    auto passwd = getpwnam(flag_uid.c_str());
    CHECK(passwd != NULL) << "Unable to get info for user " << flag_uid;
    flag_uid = passwd->pw_uid;
    CHECK_SUCCESS(Errno(initgroups(flag_uid.c_str(), getgid())));
    CHECK_SUCCESS(Errno(setuid(passwd->pw_uid)));
  } else {
    LOG(V1) << "Staying with UID=" << getuid();
  }
}

#define SECCOMP_RULE_ADD(...) \
  CHECK_SUCCESS(NegErrno(seccomp_rule_add(__VA_ARGS__)))

void CommonPrivileges(scmp_filter_ctx ctx) {
  // Very common operations, including sleeping, logging, and getting time.
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_nanosleep), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  // Mutex and other synchronization.
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(restart_syscall), 0);
  // File operations.
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fallocate), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ftruncate), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  // Signal handling and propagation to threads.
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);
  // Malloc/ringbuffer.
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
  // Malloc.
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  // Exiting threads.
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
}

scmp_filter_ctx kSkipSeccomp = scmp_filter_ctx(-1);

scmp_filter_ctx SeccompCtx() {
  if (flag_seccomp == "none") return kSkipSeccomp;
  if (flag_seccomp == "trace") return seccomp_init(SCMP_ACT_TRACE(1));
  if (flag_seccomp == "kill") return seccomp_init(SCMP_ACT_KILL);
  LOG(FATAL) << "invalid --seccomp flag: " << flag_seccomp;
  return NULL;  // unreachable
}

void DropCommonThreadPrivileges() {
  scmp_filter_ctx ctx = SeccompCtx();
  if (ctx == kSkipSeccomp) return;
  CHECK(ctx != NULL);
  CommonPrivileges(ctx);
  CHECK_SUCCESS(NegErrno(seccomp_load(ctx)));
  seccomp_release(ctx);
}

void DropIndexThreadPrivileges() {
  scmp_filter_ctx ctx = SeccompCtx();
  if (ctx == kSkipSeccomp) return;
  CHECK(ctx != NULL);
  CommonPrivileges(ctx);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rename), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
                   SCMP_A1(SCMP_CMP_EQ, O_WRONLY | O_CREAT | O_TRUNC));
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
                   SCMP_A1(SCMP_CMP_EQ, O_RDWR | O_CREAT | O_TRUNC));
  CHECK_SUCCESS(NegErrno(seccomp_load(ctx)));
  seccomp_release(ctx);
}

void DropPacketThreadPrivileges() {
  scmp_filter_ctx ctx = SeccompCtx();
  if (ctx == kSkipSeccomp) return;
  CHECK(ctx != NULL);
  CommonPrivileges(ctx);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_setup), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_submit), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_getevents), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 1,
                   SCMP_A1(SCMP_CMP_EQ, POLLIN));
  SECCOMP_RULE_ADD(
      ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 2,
      SCMP_A1(SCMP_CMP_EQ, O_WRONLY | O_CREAT | O_DSYNC | O_DIRECT),
      SCMP_A2(SCMP_CMP_EQ, 0600));
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 2,
                   SCMP_A1(SCMP_CMP_EQ, SOL_PACKET),
                   SCMP_A2(SCMP_CMP_EQ, PACKET_STATISTICS));
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rename), 0);
  CHECK_SUCCESS(NegErrno(seccomp_load(ctx)));
  seccomp_release(ctx);
}

#undef SECCOMP_RULE_ADD

Error SetAffinity(int cpu) {
  cpu_set_t cpus;
  CPU_ZERO(&cpus);
  CPU_SET(cpu, &cpus);
  return Errno(sched_setaffinity(0, sizeof(cpus), &cpus));
}

void WriteIndexes(int thread, st::ProducerConsumerQueue* write_index) {
  LOG(V1) << "Starting WriteIndexes thread " << thread;
  Watchdog dog("WriteIndexes thread " + std::to_string(thread),
               flag_fileage_sec * 3);
  pid_t tid = syscall(SYS_gettid);
  LOG_IF_ERROR(Errno(setpriority(PRIO_PROCESS, tid, flag_index_nicelevel)),
               "setpriority");
  privileges_dropped.WaitForNotification();
  DropIndexThreadPrivileges();
  while (true) {
    LOG(V1) << "Waiting for index";
    Index* i = reinterpret_cast<Index*>(write_index->Get());
    LOG(V1) << "Got index " << int64_t(i);
    if (i == NULL) {
      break;
    }
    LOG_IF_ERROR(i->Flush(), "index flush");
    LOG(V1) << "Wrote index " << int64_t(i);
    delete i;
    dog.Feed();
  }
  LOG(V1) << "Exiting write index thread";
}

bool run_threads = true;

void HandleSignals(int sig) {
  if (run_threads) {
    LOG(INFO) << "Got signal " << sig << ", stopping threads";
    run_threads = false;
  }
}

void HandleSignalsThread() {
  LOG(V1) << "Handling signals";
  struct sigaction handler;
  handler.sa_handler = &HandleSignals;
  sigemptyset(&handler.sa_mask);
  handler.sa_flags = 0;
  sigaction(SIGINT, &handler, NULL);
  sigaction(SIGTERM, &handler, NULL);
  DropCommonThreadPrivileges();
  main_complete.WaitForNotification();
  LOG(V1) << "Signal handling done";
}

void RunThread(int thread, st::ProducerConsumerQueue* write_index) {
  if (flag_threads > 1) {
    LOG_IF_ERROR(SetAffinity(thread), "set affinity");
  }
  int socktype = SOCK_RAW;
  struct tpacket_req3 options;
  memset(&options, 0, sizeof(options));
  options.tp_block_size = 1 << 20;  // it's very important this be 1MB
  options.tp_block_nr = flag_blocks;
  options.tp_frame_size = 16 << 10;  // does not matter at all
  options.tp_frame_nr = 0;           // computed for us.
  options.tp_retire_blk_tov = 10 * kNumMillisPerSecond;
  Watchdog dog("Thread " + std::to_string(thread), flag_fileage_sec * 2);

  // Set up AF_PACKET packet reading.
  PacketsV3::Builder builder;
  CHECK_SUCCESS(builder.SetUp(socktype, options));
  int fanout_id = getpid();
  if (flag_fanout_id > 0) {
    fanout_id = flag_fanout_id;
  }
  if (flag_fanout_id > 0 || flag_threads > 1) {
    CHECK_SUCCESS(builder.SetFanout(flag_fanout_type, fanout_id));
  }
  if (!flag_filter.empty()) {
    CHECK_SUCCESS(builder.SetFilter(flag_filter));
  }
  PacketsV3* v3;
  CHECK_SUCCESS(builder.Bind(flag_iface, &v3));
  std::unique_ptr<PacketsV3> cleanup(v3);

  sockets_created->Block();
  privileges_dropped.WaitForNotification();
  DropPacketThreadPrivileges();
  LOG(INFO) << "Thread " << thread << " starting to process packets";

  // Set up file writing, if requested.
  Output output(flag_aiops);

  // All dirnames are guaranteed to end with '/'.
  std::string file_dirname = flag_dir + "PKT" + std::to_string(thread) + "/";
  std::string index_dirname = flag_dir + "IDX" + std::to_string(thread) + "/";

  Packet p;
  int64_t micros = GetCurrentTimeMicros();
  CHECK_SUCCESS(output.Rotate(
      file_dirname, micros, flag_preallocate_file_mb << 10));
  Index* index = NULL;
  if (flag_index) {
    index = new Index(index_dirname, micros);
  } else {
    LOG(ERROR) << "Indexing turned off";
  }

  int64_t start = GetCurrentTimeMicros();
  int64_t lastlog = 0;
  int64_t blocks = 0;
  int64_t block_offset = 0;
  for (int64_t remaining = flag_count; remaining != 0 && run_threads;) {
    LOG_IF_ERROR(output.CheckForCompletedOps(false), "check for completed");
    int64_t current_micros = GetCurrentTimeMicros();

    // Rotate file if necessary.
    int64_t current_file_age_secs =
        (current_micros - micros) / kNumMicrosPerSecond;
    if (block_offset == flag_filesize_mb ||
        current_file_age_secs > flag_fileage_sec) {
      LOG(V1) << "Rotating file " << micros << " with " << block_offset
              << " blocks";
      // File size got too big, rotate file.
      micros = current_micros;
      block_offset = 0;
      CHECK_SUCCESS(output.Rotate(
          file_dirname, micros, flag_preallocate_file_mb << 10));
      if (flag_index) {
        write_index->Put(index);
        index = new Index(index_dirname, micros);
      }
    }
    // Read in a new block from AF_PACKET.
    Block b;
    CHECK_SUCCESS(v3->NextBlock(&b, kNumMillisPerSecond));
    if (b.Empty()) {
      continue;
    }

    // Index all packets if necessary.
    if (flag_index) {
      for (; remaining != 0 && b.Next(&p); remaining--) {
        index->Process(p, block_offset << 20);
      }
    }
    blocks++;
    block_offset++;

    // Log stats every 100MB or at least 1/minute.
    if (blocks % 100 == 0 ||
        lastlog < current_micros - 60 * kNumMicrosPerSecond) {
      lastlog = current_micros;
      double duration = (current_micros - start) * 1.0 / kNumMicrosPerSecond;
      Stats stats;
      Error stats_err = v3->GetStats(&stats);
      if (SUCCEEDED(stats_err)) {
        LOG(INFO) << "Thread " << thread << " stats: MB=" << blocks
                  << " secs=" << duration << " MBps=" << (blocks / duration)
                  << " " << stats.String();
      } else {
        LOG(ERROR) << "Unable to get stats: " << *stats_err;
      }
    }

    // Start an async write of the current block.  Could block
    // waiting for the write 'aiops' writes ago.
    CHECK_SUCCESS(output.Write(&b));
    dog.Feed();
  }
  LOG(V1) << "Finishing thread " << thread;
  // Write out the last index.
  if (flag_index) {
    write_index->Put(index);
  }
  // Close last open file.
  CHECK_SUCCESS(output.Flush());
  LOG(INFO) << "Finished thread " << thread << " successfully";
}

int Main(int argc, char** argv) {
  LOG_IF_ERROR(Errno(prctl(PR_SET_PDEATHSIG, SIGTERM)), "prctl PDEATHSIG");
  ParseOptions(argc, argv);
  LOG(V1) << "Stenotype running with these arguments:";
  for (int i = 0; i < argc; i++) {
    LOG(V1) << i << ":\t\"" << argv[i] << "\"";
  }
  LOG(INFO) << "Starting...";
  sockets_created = new Barrier(flag_threads + 1);

  // Sanity check flags and setup options.
  CHECK(flag_filesize_mb <= 4 << 10);
  CHECK(flag_filesize_mb > 1);
  CHECK(flag_filesize_mb > flag_aiops);
  CHECK(flag_blocks > 16);  // arbitrary lower limit.
  CHECK(flag_threads >= 1);
  CHECK(flag_aiops <= flag_blocks / 2);
  CHECK(flag_dir != "");
  if (flag_dir[flag_dir.size() - 1] != '/') {
    flag_dir += "/";
  }

  // Start a thread whose sole purpose is to handle signals.
  std::thread signal_thread(&HandleSignalsThread);
  signal_thread.detach();

  // Block stopping signals, they'll be handled by the HandleSignalsThread.
  sigset_t sigset;
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGINT);
  sigaddset(&sigset, SIGTERM);
  CHECK_SUCCESS(Errno(pthread_sigmask(SIG_BLOCK, &sigset, NULL)));

  auto write_indexes = new st::ProducerConsumerQueue[flag_threads];
  // To avoid blocking on index writes, each writer thread has a secondary
  // thread just for creating and writing the indexes.  We pass to-write
  // indexes through to the writing thread via the write_index FIFO queue.
  std::vector<std::thread*> index_threads;
  if (flag_index) {
    LOG(V1) << "Starting indexing threads";
    for (int i = 0; i < flag_threads; i++) {
      std::thread* t = new std::thread(&WriteIndexes, i, &write_indexes[i]);
      index_threads.push_back(t);
    }
  }

  LOG(V1) << "Starting writing threads";
  std::vector<std::thread*> threads;
  for (int i = 0; i < flag_threads; i++) {
    LOG(V1) << "Starting thread " << i;
    threads.push_back(new std::thread(&RunThread, i, &write_indexes[i]));
  }
  sockets_created->Block();
  DropPrivileges();
  privileges_dropped.Notify();
  DropCommonThreadPrivileges();

  for (auto thread : threads) {
    LOG(V1) << "===============Waiting for thread==============";
    CHECK(thread->joinable());
    thread->join();
    LOG(V1) << "Thread finished";
    delete thread;
  }
  LOG(V1) << "Finished all threads";
  if (flag_index) {
    for (int i = 0; i < flag_threads; i++) {
      LOG(V1) << "Closing write index queue " << i << ", waiting for thread";
      write_indexes[i].Close();
      CHECK(index_threads[i]->joinable());
      index_threads[i]->join();
      LOG(V1) << "Index thread finished";
      delete index_threads[i];
    }
  }
  delete[] write_indexes;
  LOG(INFO) << "Process exiting successfully";
  main_complete.Notify();
  return 0;
}

}  // namespace st

int main(int argc, char** argv) { return st::Main(argc, argv); }
