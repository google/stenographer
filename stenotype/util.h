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

#ifndef STENOGRAPHER_UTIL_H_
#define STENOGRAPHER_UTIL_H_

// Contains small helper functions and types used throughout stenographer code.

#include <stdint.h>
#include <stdio.h>
#include <time.h>      // strftime(), gmtime(), time(),
#include <sys/time.h>  // gettimeofday()
#include <pthread.h>   // pthread_self()
#include <stdlib.h>
#include <string.h>
#include <execinfo.h>  // backtrace(), backtrace_symbols()

#include <condition_variable>
#include <deque>
#include <iomanip>   // setw, setfill
#include <iostream>  // cerr
#include <memory>
#include <mutex>
#include <sstream>  // stringstream
#include <string>   // string
#include <thread>

namespace {

struct timespec clock_realtime, clock_monotonic;
clockid_t clock_mono_id = CLOCK_MONOTONIC;
bool InitTime() {
  clock_gettime(CLOCK_REALTIME, &clock_realtime);
#ifdef CLOCK_MONOTONIC_RAW
  // If monotinic raw clock is supported and available, let's use that.
  if (!clock_gettime(CLOCK_MONOTONIC_RAW, &clock_monotonic)) {
    clock_mono_id = CLOCK_MONOTONIC_RAW;
    return true;
  }
#endif
  clock_gettime(CLOCK_MONOTONIC, &clock_monotonic);
  return true;
}
bool run_init_time = InitTime();

}  // namespace

namespace st {

#define DISALLOW_COPY_AND_ASSIGN(name) \
  name(const name&);                   \
  name(const name&&);                  \
  void operator=(const name&)

const int64_t kNumNanosPerMicro = 1000;
const int64_t kNumMicrosPerMilli = 1000;
const int64_t kNumMillisPerSecond = 1000;
const int64_t kNumNanosPerMilli = kNumNanosPerMicro * kNumMicrosPerMilli;
const int64_t kNumMicrosPerSecond = kNumMicrosPerMilli * kNumMillisPerSecond;
const int64_t kNumNanosPerSecond =
    kNumMillisPerSecond * kNumMicrosPerMilli * kNumNanosPerMicro;

inline int64_t GetCurrentTimeNanos() {
  struct timespec tv;
  clock_gettime(clock_mono_id, &tv);
  int64_t secs = clock_realtime.tv_sec - clock_monotonic.tv_sec + tv.tv_sec;
  int64_t nsecs = clock_realtime.tv_nsec - clock_monotonic.tv_nsec + tv.tv_nsec;
  return secs * 1000000000 + nsecs;
}
inline int64_t GetCurrentTimeMicros() { return GetCurrentTimeNanos() / 1000; }
inline void SleepForNanoseconds(int64_t nanos) {
  if (nanos <= 0) {
    return;
  }
  struct timespec tv;
  tv.tv_sec = nanos / kNumNanosPerSecond;
  tv.tv_nsec = nanos % kNumNanosPerSecond;
  while (EINTR == clock_nanosleep(CLOCK_MONOTONIC, 0, &tv, &tv)) {
  }
}
inline void SleepForMicroseconds(int64_t micros) {
  SleepForNanoseconds(micros * kNumNanosPerMicro);
}
inline void SleepForSeconds(double seconds) {
  SleepForNanoseconds(seconds * kNumNanosPerSecond);
}

////////////////////////////////////////////////////////////////////////////////
//// Logging helpers
//
// Simple methods for logging intersting events.
// LOG(INFO) << "blah";  // normal logging message
// LOG(FATAL) << "blah";  // log, then crash the program.  something is wrong.
// CHECK(b) << "blah";  // if 'b' is false, crash with given message.

namespace {

const size_t kTimeBufferSize = 20;
const char* kTimeFormat = "%Y-%m-%dT%H:%M:%S";

}  // namespace

class LogLine {
 public:
  LogLine(bool crash, const char* file, int line) : crash_(crash) {
    FillTimeBuffer();
    uint32_t tid = uint32_t(pthread_self()) >> 8;  // first bits always 0.
    ss_ << std::setfill('0') << time_buffer_ << "." << std::setw(6)
        << tv_.tv_usec << "Z T:" << std::hex << std::setw(6) << tid
        << std::setw(0) << std::dec << " [" << file << ":" << line << "] ";
  }
  ~LogLine() {
    ss_ << "\n";
    std::cerr << ss_.str() << std::flush;
    if (crash_) {
      std::cerr << "ABORTABORTABORT" << std::endl;
      void* backtraces[32];
      int size = backtrace(backtraces, 32);
      char** symbols = backtrace_symbols(backtraces, size);
      for (int i = 0; i < size; i++) {
        std::cerr << symbols[i] << std::endl;
      }
      free(symbols);
      abort();
    }
  }

  template <class T>
  LogLine& operator<<(const T& data) {
    ss_ << data;
    return *this;
  }

 private:
  void FillTimeBuffer() {
    gettimeofday(&tv_, NULL);
    struct tm* timeinfo = gmtime(&tv_.tv_sec);
    size_t len = strftime(time_buffer_, kTimeBufferSize, kTimeFormat, timeinfo);
    if (len + 1 != kTimeBufferSize) {  // returned num bytes doesn't include \0
      strcpy(time_buffer_, "STRFTIME_ERROR");
    }
  }

  std::stringstream ss_;
  struct timeval tv_;
  char time_buffer_[kTimeBufferSize];
  bool crash_;

  DISALLOW_COPY_AND_ASSIGN(LogLine);
};

extern int logging_verbose_level;
#define LOGGING_FATAL_CRASH true
#define LOGGING_ERROR_CRASH false
#define LOGGING_INFO_CRASH false
#define LOGGING_V1_CRASH false
#define LOGGING_V2_CRASH false
#define LOGGING_V3_CRASH false
#define LOGGING_V4_CRASH false

#define LOGGING_FATAL_LOG true
#define LOGGING_ERROR_LOG true
#define LOGGING_INFO_LOG (logging_verbose_level > 0)
#define LOGGING_V1_LOG (logging_verbose_level > 1)
#define LOGGING_V2_LOG (logging_verbose_level > 2)
#define LOGGING_V3_LOG (logging_verbose_level > 3)
#define LOGGING_V4_LOG (logging_verbose_level > 4)

#ifndef LOG
#define LOG(level)           \
  if (LOGGING_##level##_LOG) \
  ::st::LogLine(LOGGING_##level##_CRASH, __FILE__, __LINE__)
#endif
#ifndef CHECK
#define CHECK(expr) \
  if (!(expr)) LOG(FATAL) << "CHECK(" #expr ") "
#endif

typedef std::unique_ptr<std::string> Error;

#define SUCCEEDED(x) ((x).get() == NULL)
#define SUCCESS NULL

#define ERROR(x) Error(new std::string(x))

#define RETURN_IF_ERROR(status, msg)                \
  do {                                              \
    Error __return_if_error_status__ = (status);    \
    if (!SUCCEEDED(__return_if_error_status__)) {   \
      __return_if_error_status__->append(" <- ");   \
      __return_if_error_status__->append(msg);      \
      return std::move(__return_if_error_status__); \
    }                                               \
  } while (false)

#define LOG_IF_ERROR(status, msg)                            \
  do {                                                       \
    Error __log_if_error_status__ = (status);                \
    if (!SUCCEEDED(__log_if_error_status__)) {               \
      LOG(ERROR) << msg << ": " << *__log_if_error_status__; \
    }                                                        \
  } while (false)

#define CHECK_SUCCESS(x)                                                   \
  do {                                                                     \
    Error __check_success_error__ = (x);                                   \
    CHECK(SUCCEEDED(__check_success_error__)) << #x << ": "                \
                                              << *__check_success_error__; \
  } while (false)

#define REPLACE_IF_ERROR(initial, replacement)         \
  do {                                                 \
    Error __replacement_error__ = (replacement);       \
    if (!SUCCEEDED(__replacement_error__)) {           \
      if (!SUCCEEDED(initial)) {                       \
        LOG(ERROR) << "replacing error: " << *initial; \
      }                                                \
      initial = std::move(__replacement_error__);      \
    }                                                  \
  } while (false)

////////////////////////////////////////////////////////////////////////////////
//// Synchronization primitives
//
// The very simple Mutex class, and its RAII locker Mutex::Locker provide very
// simple blocking locks/unlocks wrapping a pthreads mutex.

// Barrier provides a barrier for multiple threads.
class Barrier {
 public:
  explicit Barrier(int threads) : threads_(threads), count_(0) {}
  ~Barrier() {}
  void Block() {
    std::unique_lock<std::mutex> lock(mu_);
    if (++count_ >= threads_) {
      lock.unlock();
      cond_.notify_all();
    } else {
      while (count_ < threads_) {
        cond_.wait(lock);
      }
    }
  }

 private:
  int threads_;
  int count_;
  std::mutex mu_;
  std::condition_variable cond_;

  DISALLOW_COPY_AND_ASSIGN(Barrier);
};

// Notification allows multiple threads to wait for one thread to do something.
class Notification {
 public:
  Notification() : waiting_(true) {}
  ~Notification() {}
  void WaitForNotification() {
    std::unique_lock<std::mutex> lock(mu_);
    while (waiting_) {
      cond_.wait(lock);
    }
  }
  void Notify() {
    mu_.lock();
    CHECK(waiting_);
    waiting_ = false;
    mu_.unlock();
    cond_.notify_all();
  }

 private:
  bool waiting_;
  std::mutex mu_;
  std::condition_variable cond_;

  DISALLOW_COPY_AND_ASSIGN(Notification);
};

// ProducerConsumerQueue is a very simple thread-safe FIFO queue.
class ProducerConsumerQueue {
 public:
  ProducerConsumerQueue() : closed_(false) {}
  ~ProducerConsumerQueue() {}

  void Put(void* val) {
    CHECK(!closed_);
    std::unique_lock<std::mutex> lock(mu_);
    d_.push_back(val);
    lock.unlock();
    cond_.notify_one();
  }
  void* Get() {
    std::unique_lock<std::mutex> lock(mu_);
    while (d_.empty() && !closed_) {
      cond_.wait(lock);
    }
    if (d_.empty() && closed_) {
      return NULL;
    }
    void* ret = d_.front();
    d_.pop_front();
    return ret;
  }
  void Close() {
    std::unique_lock<std::mutex> lock(mu_);
    closed_ = true;
    lock.unlock();
    cond_.notify_all();
  }

 private:
  std::mutex mu_;
  std::condition_variable cond_;
  bool closed_;
  std::deque<void*> d_;
  DISALLOW_COPY_AND_ASSIGN(ProducerConsumerQueue);
};

// Errno returns a util::Status based on the current value of errno and the
// success flag.  If success is true, returns OK.  Otherwise, returns a
// FAILED_PRECONDITION error based on errno.
inline Error Errno(int ret = -1) {
  if (ret >= 0 || errno == 0) {
    return SUCCESS;
  }
  return ERROR(strerror(errno));
}

// Linux libaio and libseccomp use a different errno convention than normal
// syscalls.  Instead of returning -1 and setting errno, they return -errno
// on errors.  This function takes in that return value and returns OK if
// ret >= 0 or an Errno error based on the negative return value.
inline Error NegErrno(int ret) {
  if (ret < 0) {
    return ERROR(strerror(-ret));
  }
  return SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//// Filesystem helpers.

std::string Basename(const std::string& filename);
std::string Dirname(const std::string& filename);
inline std::string HiddenFile(const std::string& dirname, int64_t micros) {
  CHECK(dirname[dirname.size() - 1] == '/');
  return dirname + "." + std::to_string(micros);
}
inline std::string UnhiddenFile(const std::string& dirname, int64_t micros) {
  CHECK(dirname[dirname.size() - 1] == '/');
  return dirname + std::to_string(micros);
}

// Watchdog is a simple thread which causes a process crash if certain code
// paths aren't hit on a regular basis.
//
// Usage:
//   Watchdog dog("description", 5 /*seconds*/);
//   while (true) {
//     dostuff();
//     dog.Feed();  // If not called every 5 seconds, crashes.
//   }
//   // dog falls out of scope, its thread is canceled and it quietly goes away.
class Watchdog {
 private:
  void Watch() {
    auto last = ctr_;
    while (true) {
      auto now = GetCurrentTimeMicros();
      auto recheck = now + kNumMicrosPerSecond * seconds_;
      for (; last == ctr_ && !done_ && now < recheck;
           now = GetCurrentTimeMicros()) {
        SleepForSeconds(std::min(1.0, double(seconds_) / 10));
      }
      if (done_) {
        return;
      } else if (last != ctr_) {
        LOG(V2) << "Fed watchdog: " << description_;
        last = ctr_;
        continue;
      }
      LOG(FATAL) << "WATCHDOG FAILURE: " << description_;
    }
  }

 public:
  Watchdog(std::string description, int seconds)
      : description_(description), seconds_(seconds), ctr_(0), done_(false) {
    t_ = new std::thread(&Watchdog::Watch, this);
  }
  ~Watchdog() {
    done_ = true;
    t_->join();
    delete t_;
  }
  void Feed() { ctr_++; }

 private:
  std::thread* t_;
  std::string description_;
  int seconds_;
  uint64_t ctr_;
  bool done_;
};

}  // namespace st

#endif  // STENOGRAPHER_UTIL_H_
