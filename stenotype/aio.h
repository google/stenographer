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

#ifndef EXPERIMENTAL_USERS_GCONNELL_AFPACKET_AIO_H_
#define EXPERIMENTAL_USERS_GCONNELL_AFPACKET_AIO_H_

#include <stddef.h>
#include <libaio.h>

#include <set>
#include <string>

#include "packets.h"
#include "util.h"

namespace st {

namespace io {
class SingleFile;  // Internal class, used by Output.
}  // namespace io

// Output implements an asynchronous, single-threaded method of writing
// contiguous data to a file.  At any given time, Output will maintain an
// ordered circular queue of asynchronous IO operations which it has submitted
// to the kernel.  PWrite requests will create a new such IO operation and
// submit it, flushing whatever operation it replaces, then returning.
// File closing also happens asynchronously.  A request to close a file does not
// immediately close it.  Instead, it schedules the close to happen after the
// last PWrite to that file finishes.
class Output {
 public:
  // Create a new async IO queue with aiops slots for IO operations.
  // This class originally starts out with no file... an Open call must occur
  // before any PWrites to open a file.
  explicit Output(int aiops);
  // Flush all files on exit.
  virtual ~Output();
  // Open a new file.  Will fail if a file is already open.
  // If initial_size > 0, will attempt to preallocate the file to be
  // that many bytes.
  Error Rotate(
      const std::string& dirname, int64_t micros, int64_t initial_size);
  // Close and flush all files.
  Error Flush();
  // Write the given Block out to the given offset in the current file,
  // asynchronously.  This call takes ownership of the underlying block (via a
  // b->Swap()), so you're free to discard your local block after this call.
  // The block will be freed once its IO operation has completed.
  Error Write(Block* b);

  // Check to see if any outstanding IO operations can be marked as completed
  // and their blocks returned to the kernel.  If 'block' is set, blocks until
  // at least one operation has been completed.
  Error CheckForCompletedOps(bool block);

 private:
  Error SetUp();
  int Outstanding();
  Error MaybeCloseFile(io::SingleFile* file);

  io_context_t ctx_;
  int max_ops_;
  io::SingleFile* current_;
  std::set<io::SingleFile*> files_;

  DISALLOW_COPY_AND_ASSIGN(Output);
};

}  // namespace st

#endif  // EXPERIMENTAL_USERS_GCONNELL_AFPACKET_AIO_H_
