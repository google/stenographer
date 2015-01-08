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

# This is not meant to be a permanent addition to stenographer, more of a
# hold-over until we can get actual debian packaging worked out.  Also, this
# will probably guide the debian work by detailing all the actual stuff that
# needs to be done to install stenographer correctly.

BINDIR="${BINDIR-/usr/local/bin}"
OUTDIR="${OUTDIR-/tmp/stenographer}"

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
  sudo killall "$1" "$@" 2>/dev/null >/dev/null
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

cd "$(dirname $0)"

Info "Making sure we have sudo access"
sudo cat /dev/null

Info "Killing aleady-running processes"
ReallyKill stenographer
ReallyKill stenotype

set -e
InstallPackage libaio-dev
InstallPackage libleveldb-dev
InstallPackage libsnappy-dev
InstallPackage g++
InstallPackage libcap2-bin
InstallPackage libseccomp-dev

if ! grep -q stenographer /etc/passwd; then
  Info "Setting up stenographer user"
  sudo adduser \
    --system \
    --group \
    --no-create-home \
    stenographer
fi

if [ -d /etc/security/limits.d ]; then
  if [ ! -f /etc/security/limits.d/stenographer.conf ]; then
    Info "Setting up stenographer limits"
    sudo cp limits.conf /etc/security/limits.d/stenographer.conf
  fi
fi

if [ ! -d /etc/stenographer/certs ]; then
  Info "Setting up stenographer /etc directory"
  sudo mkdir -p /etc/stenographer/certs
  if [ ! -f /etc/stenographer/config ]; then
    sudo cp -vf sample_config /etc/stenographer/config
  fi
  sudo chown -R stenographer:stenographer /etc/stenographer
fi

if [ ! -d "$OUTDIR" ]; then
  Info "Setting up initial steno output in $OUTDIR"
  sudo mkdir -p "$OUTDIR"/{idx,pkt}
  sudo chown -R stenographer:root "$OUTDIR"
  sudo chmod -R 0700 "$OUTDIR"
fi

Info "Building stenographer"
go build
sudo cp -vf stenographer "$BINDIR/stenographer"
sudo chown stenographer:root "$BINDIR/stenographer"
sudo chmod 0700 "$BINDIR/stenographer"

Info "Building stenotype"
pushd stenotype
make
popd
sudo cp -vf stenotype/stenotype "$BINDIR/stenotype"
sudo chown stenographer:root "$BINDIR/stenotype"
sudo chmod 0700 "$BINDIR/stenotype"
sudo setcap 'CAP_NET_RAW+ep CAP_NET_ADMIN+ep CAP_IPC_LOCK+ep' "$BINDIR/stenotype"

Info "Copying stenoread"
sudo cp -vf stenoread "$BINDIR/stenoread"
sudo chown stenographer:stenographer "$BINDIR/stenoread"
sudo chmod 0750 "$BINDIR/stenoread"

LOG="$OUTDIR/log"
Info "Starting stenographer, see logs in '$LOG'"
# The weird sudo tee stuff is to correctly use sudo permissions when directing
# output to a file.
sudo -u stenographer -b "$BINDIR/stenographer" \
    2>&1 | sudo -u stenographer -b tee "$LOG" > /dev/null &

Info "Checking for running processes..."
sleep 5
if Running stenographer; then
  Info "  * Stenographer up and running"
else
  Error "  !!! Stenographer not running !!!"
  sudo cat $LOG
  exit 1
fi
if Running stenotype; then
  Info "  * Stenotype up and running"
else
  Error "  !!! Stenotype not running !!!"
  sudo cat $LOG
  exit 1
fi
Info "Tailing output, Ctrl-C will stop tailing, but stenographer will still run"
exec sudo tail -f $LOG
