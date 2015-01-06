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

int logging_verbose_level = -1;  // by default, log ERROR only

// When implementing basename and dirname, we copy everything to a buffer, then
// call libgen's basename()/dirname() functions on that buffer.  We do this
// because those calls can modify the underlying character buffer.  We also, for
// extra safety, add an extra null byte onto the end of the filename, in case
// for some very strange reason we're passed a filename without one.

string Basename(const string& filename) {
  char copy[filename.size() + 1];
  memcpy(copy, filename.data(), filename.size());
  copy[filename.size()] = 0;
  return string(basename(copy));
}

string Dirname(const string& filename) {
  char copy[filename.size() + 1];
  memcpy(copy, filename.data(), filename.size());
  copy[filename.size()] = 0;
  return string(dirname(copy));
}

}  // namespace st
