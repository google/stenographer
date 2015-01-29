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

# Some simple helper functions for writing bash scripts.

function Info {
  echo -e -n '\e[7m'
  echo "$@"
  echo -e -n '\e[0m'
}

function Error {
  echo -e -n '\e[41m'
  echo "$@"
  echo -e -n '\e[0m'
}

function Kill {
  KILLCMD="${KILLCMD-killall}"
  sudo "$KILLCMD" "$@" 2>/dev/null >/dev/null
}

function Running {
  Kill -0 "$1"
}

function ReallyKill {
  if Running "$1"; then
    Info "Killing '$1'"
    Kill "$1"
    sleep 5
  fi
  if Running "$1"; then
    Info "Killing '$1' again"
    Kill "$1"
    sleep 5
  fi
  if Running "$1"; then
    Error "Killing '$1' with fire"
    Kill -9 "$1"
    sleep 1
  fi
}

function InstallPackage {
  Info "Checking for package '$1'"
  if ! dpkg -s $1 >/dev/null 2>/dev/null; then
    Info "Have to install package $1"
    sudo apt-get install $1
  fi
}

function SetCapabilities {
  sudo setcap 'CAP_NET_RAW+ep CAP_NET_ADMIN+ep CAP_IPC_LOCK+ep' "$1"
}

function Sleep {
  Info "Sleeping until $(date --date "$1 sec")"
  sleep $1
}
