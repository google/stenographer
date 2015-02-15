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

#include "util.h"

#include <libgen.h>    // basename(), dirname()
#include <sys/stat.h>  // mkdir()

namespace st {

int logging_verbose_level = 0;

// When implementing basename and dirname, we copy everything to a buffer, then
// call libgen's basename()/dirname() functions on that buffer.  We do this
// because those calls can modify the underlying character buffer.  We also, for
// extra safety, add an extra null byte onto the end of the filename, in case
// for some very strange reason we're passed a filename without one.

std::string Basename(const std::string& filename) {
  char copy[filename.size() + 1];
  memcpy(copy, filename.data(), filename.size());
  copy[filename.size()] = 0;
  return std::string(basename(copy));
}

std::string Dirname(const std::string& filename) {
  char copy[filename.size() + 1];
  memcpy(copy, filename.data(), filename.size());
  copy[filename.size()] = 0;
  return std::string(dirname(copy));
}

void Barrier::Block() {
  std::unique_lock<std::mutex> lock(mu_);
  count_++;
  if (count_ >= threads_) {
    lock.unlock();
    cond_.notify_all();
  } else {
    while (count_ < threads_) {
      cond_.wait(lock);
    }
  }
}

void Notification::WaitForNotification() {
  std::unique_lock<std::mutex> lock(mu_);
  while (waiting_) {
    cond_.wait(lock);
  }
}

void Notification::Notify() {
  mu_.lock();
  CHECK(waiting_);
  waiting_ = false;
  mu_.unlock();
  cond_.notify_all();
}

void ProducerConsumerQueue::Put(void* val) {
  CHECK(val != NULL);
  CHECK(!closed_);
  std::unique_lock<std::mutex> lock(mu_);
  d_.push_back(val);
  lock.unlock();
  cond_.notify_one();
}

void* ProducerConsumerQueue::Get() {
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

void ProducerConsumerQueue::Close() {
  std::unique_lock<std::mutex> lock(mu_);
  closed_ = true;
  lock.unlock();
  cond_.notify_all();
}

void Watchdog::Watch() {
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

Watchdog::Watchdog(std::string description, int seconds)
    : description_(description), seconds_(seconds), ctr_(0), done_(false) {
  t_ = new std::thread(&Watchdog::Watch, this);
}

Watchdog::~Watchdog() {
  done_ = true;
  t_->join();
  delete t_;
}

void Watchdog::Feed() { ctr_++; }

}  // namespace st
