#!/bin/bash

# Copyright 2014 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# At the moment, we're really not portable at all... if you happen to run on a
# recent Ubuntu, great.  Otherwise, all bets are off.
#
# We do plan to improve the build process for other Linux distros, but since we
# rely very heavily on many Linux-specific features (particularly AF_PACKET), we
# have no plans to make this portable to non-Linux or even older Linux distros.

function InstallPackage {
  echo "Checking for package '$1'"
  if ! dpkg -l $1 >/dev/null 2>/dev/null; then
    echo "Have to install package $1"
    sudo apt-get install $1
  fi
}

InstallPackage libaio-dev
InstallPackage libleveldb-dev
InstallPackage libsnappy-dev

echo "Building binary"
g++ --std=c++0x \
  -o stenotype \
  -g -O3 -rdynamic -Wall \
  aio.cc util.cc packets.cc index.cc stenotype.cc \
  -lleveldb -lrt -laio -lpthread -lsnappy
