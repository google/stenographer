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
  "$KILLCMD" "$@" 2>/dev/null >/dev/null
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

function CheckCentosRepos {
  # snappy-devel is in Power Tools in CentOS 8, which is disabled by default
  if grep 'VERSION_ID="8"' /etc/os-release >/dev/null && ! yum repolist | grep PowerTools >/dev/null; then
    Error "You're using CentOS 8 and have Power Tools repository disabled, please enable it before running this script."
    Error "  # yum config-manager --set-enabled PowerTools"
  fi
}

function InstallJq {
  local _url="https://github.com/stedolan/jq/releases/download/jq-1.5rc2/jq-linux-x86_64"
  if (! which jq &>/dev/null); then
    Info "Installing jq ..."
    curl -s -L -J $_url | tee /usr/local/bin/jq >/dev/null;
    chmod +x /usr/local/bin/jq;
  fi
}

function InstallDependencies {
  Info "Installing dependencies"

  case $1 in
    centos)
      CheckCentosRepos
      InstallJq
      yum install -y --enablerepo=PowerTools libaio-devel \
                       leveldb-devel \
                       snappy-devel \
                       gcc-c++ \
                       make \
                       libcap-devel \
                       libseccomp-devel
      ;;
    debian)
      apt-get install libaio-dev \
                           libleveldb-dev \
                           libsnappy-dev \
                           g++ \
                           libcap2-bin \
                           libseccomp-dev \
                           jq \
                           openssl
      ;;
  esac
}

function SetCapabilities {
  setcap 'CAP_NET_RAW+ep CAP_NET_ADMIN+ep CAP_IPC_LOCK+ep' "$1"
}

function Sleep {
  Info "Sleeping until $(date --date "$1 sec")"
  sleep $1
}
