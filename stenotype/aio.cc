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

#include "aio.h"

#include <errno.h>   // errno
#include <fcntl.h>   // open()
#include <unistd.h>  // close()
#include <libaio.h>

#include <string>

#include "util.h"

namespace st {

namespace io {

class SingleFile;

class PWrite {
 public:
  PWrite(Block* b, SingleFile* f) {
    LOG(V3) << "PWriteBlockConstructor b" << int64_t(b) << " INTO b"
            << int64_t(&block);
    block.Swap(b);
    file = f;
  }
  ~PWrite() { LOG(V3) << "PWriteBLockDestructor b" << int64_t(&block); }

  Error Done(io_event* evt);

  iocb cb;
  Block block;
  SingleFile* file;

 private:
  DISALLOW_COPY_AND_ASSIGN(PWrite);
};

class SingleFile {
 public:
  SingleFile(Output* file, const std::string& dirname, int64_t micros, int fd)
      : file_(file),
        fd_(fd),
        offset_(0),
        truncate_(-1),
        hidden_name_(HiddenFile(dirname, micros)),
        unhidden_name_(UnhiddenFile(dirname, micros)) {}
  ~SingleFile();
  void Write(io_context_t ctx, Block* b);
  int Outstanding() { return outstanding_.size(); }
  void RemoveOutstanding(PWrite* write) {
    CHECK(outstanding_.erase(write) == 1);
    LOG(V2) << "File has " << outstanding_.size() << " remaining ops";
  }
  void RequestClose() { truncate_ = offset_; }
  bool Closable() { return outstanding_.size() == 0 && truncate_ >= 0; }
  Error Close();

 private:
  Output* file_;
  int fd_;
  int64_t offset_;
  int64_t truncate_;
  std::string hidden_name_;
  std::string unhidden_name_;
  std::set<PWrite*> outstanding_;

  DISALLOW_COPY_AND_ASSIGN(SingleFile);
};

Error PWrite::Done(io_event* event) {
  long bytes_written = static_cast<long>(event->res);
  Error result;
  if (bytes_written < 0) {
    result = NegErrno(bytes_written);
  } else if (bytes_written < int64_t(block.Data().size())) {
    result = ERROR("write truncated");
  }
  file->RemoveOutstanding(this);
  delete this;
  return move(result);
}

SingleFile::~SingleFile() {
  CHECK(outstanding_.size() == 0);
  CHECK(fd_ == 0);
}

void SingleFile::Write(io_context_t ctx, Block* b) {
  auto data = b->Data();
  PWrite* write = new PWrite(b, this);
  iocb* cb = &write->cb;
  io_prep_pwrite(cb, fd_, const_cast<char*>(data.data()), data.size(), offset_);
  offset_ += data.size();
  cb->data = reinterpret_cast<void*>(write);
  outstanding_.insert(write);
  int ret = 1;
  int64_t deadline = GetCurrentTimeMicros() + kNumMicrosPerSecond;
  while (GetCurrentTimeMicros() < deadline || ret > 0) {
    ret = io_submit(ctx, 1, &cb);
    if (ret != 0 && ret != -EAGAIN) break;
    SleepForSeconds(0.001);
  }
  CHECK_SUCCESS(NegErrno(ret));
}

Error SingleFile::Close() {
  CHECK(Closable());
  LOG(INFO) << "Closing " << hidden_name_ << " (" << fd_ << "), truncating to "
            << (truncate_ >> 20) << "MB and moving to " << unhidden_name_;
  LOG_IF_ERROR(Errno(ftruncate(fd_, truncate_)), "ftruncate");
  RETURN_IF_ERROR(Errno(close(fd_)), "close");
  fd_ = 0;
  RETURN_IF_ERROR(Errno(rename(hidden_name_.c_str(), unhidden_name_.c_str())),
                  "rename");
  return SUCCESS;
}

}  // namespace io

Output::Output(int aiops) : ctx_(NULL), max_ops_(aiops), current_(NULL) {
  CHECK_SUCCESS(SetUp());
}

Output::~Output() { CHECK_SUCCESS(Flush()); }

Error Output::SetUp() {
  int ret;
  for (int i = 0; i < 10; i++) {
    ret = io_setup(max_ops_, &ctx_);
    if (ret != -EAGAIN) {
      break;
    }
    SleepForSeconds(1);
    LOG(V1) << "io_setup retrying";
  }
  return NegErrno(ret);
}

Error Output::CheckForCompletedOps(bool block) {
  Error result;
  io_event events[4];
  int ret;
  do {
    // Unlike other syscalls, io_getevents returns -errno, instead of
    // setting errno and returning -1.
    ret = io_getevents(ctx_, block ? 1 : 0, 4, events, NULL);
  } while (ret == -EINTR);
  RETURN_IF_ERROR(NegErrno(ret), "io_getevents");
  for (int i = 0; i < ret; i++) {
    auto aio = reinterpret_cast<io::PWrite*>(events[i].obj->data);
    auto file = aio->file;
    REPLACE_IF_ERROR(result, aio->Done(&events[i]));
    REPLACE_IF_ERROR(result, MaybeCloseFile(file));
  }
  return result;
}

Error Output::MaybeCloseFile(io::SingleFile* file) {
  if (file->Closable()) {
    RETURN_IF_ERROR(file->Close(), "closing file");
    files_.erase(file);
    delete file;
  }
  return SUCCESS;
}

Error Output::Rotate(const std::string& dirname, int64_t micros,
                     int64_t initial_size) {
  if (current_) {
    current_->RequestClose();
    RETURN_IF_ERROR(MaybeCloseFile(current_), "maybe close");
    current_ = NULL;
  }
  std::string name = HiddenFile(dirname, micros);
  int fd = open(name.c_str(), O_CREAT | O_WRONLY | O_DSYNC | O_DIRECT, 0600);
  LOG(INFO) << "Opening packet file " << name << ": " << fd;
  RETURN_IF_ERROR(Errno(fd > 0), "open");
  if (initial_size > 0) {
    LOG_IF_ERROR(Errno(0 <= fallocate(fd, 0, 0, initial_size)), "fallocate");
  }
  current_ = new io::SingleFile(this, dirname, micros, fd);
  files_.insert(current_);
  return SUCCESS;
}

Error Output::Flush() {
  if (current_ != NULL) {
    current_->RequestClose();
    current_ = NULL;
  }
  while (files_.size()) {
    RETURN_IF_ERROR(CheckForCompletedOps(true), "flush");
  }
  return SUCCESS;
}

int Output::Outstanding() {
  int outstanding = 0;
  for (auto file : files_) {
    outstanding += file->Outstanding();
  }
  return outstanding;
}

Error Output::Write(Block* b) {
  if (current_ == NULL) {
    return ERROR("no file");
  }
  while (Outstanding() >= max_ops_) {
    RETURN_IF_ERROR(CheckForCompletedOps(true), "check completed");
  }
  current_->Write(ctx_, b);
  return SUCCESS;
}

}  // namespace st
