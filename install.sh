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

BINDIR="${BINDIR-/usr/bin}"

cd "$(dirname $0)"
source lib.sh

set -e

# Detect distribution for automatic dependency installation
DISTRO=
OS_RELEASE_ID=`cat /etc/os-release | perl -n -e '/^ID=\"?([a-zA-Z ]+)\"?/ && print "$1\n"'`

case $OS_RELEASE_ID in
  debian|ubuntu)
    DISTRO=debian
    ;;
  centos)
    DISTRO=centos
    ;;
  *)
    Error "Your distribution \"$OS_RELEASE_ID\" is not suported"
    exit 1
    ;;
esac

Info "Making sure we have sudo access"
sudo cat /dev/null

InstallDependencies $DISTRO

Info "Building stenographer"
go build

Info "Building stenotype"
pushd stenotype
make
popd

set +e
Info "Killing aleady-running processes"
sudo service stenographer stop
ReallyKill stenographer
ReallyKill stenotype
set -e

if ! id stenographer >/dev/null 2>&1; then
  Info "Setting up stenographer user"
  sudo adduser --system --no-create-home stenographer
fi
if ! getent group stenographer >/dev/null 2>&1; then
  Info "Setting up stenographer group"
  sudo addgroup --system stenographer
fi

if [ ! -f /etc/security/limits.d/stenographer.conf ]; then
  Info "Setting up stenographer limits"
  sudo cp -v configs/limits.conf /etc/security/limits.d/stenographer.conf
fi

if [ -d /etc/init/ ]; then
  if [ ! -f /etc/init/stenographer.conf ]; then
    Info "Setting up stenographer upstart config"
    sudo cp -v configs/upstart.conf /etc/init/stenographer.conf
    sudo chmod 0644 /etc/init/stenographer.conf
  fi
fi

if [ -d /lib/systemd/system/ ]; then
  if [ ! -f /lib/systemd/system/stenographer.service ]; then
    Info "Setting up stenographer systemd config"
    sudo cp -v configs/systemd.conf /lib/systemd/system/stenographer.service
    sudo chmod 644 /lib/systemd/system/stenographer.service
  fi
fi

if [ ! -d /etc/stenographer/certs ]; then
  Info "Setting up stenographer /etc directory"
  sudo mkdir -p /etc/stenographer/certs
  sudo chown -R root:root /etc/stenographer/certs
  if [ ! -f /etc/stenographer/config ]; then
    sudo cp -vf configs/steno.conf /etc/stenographer/config
    sudo chown root:root /etc/stenographer/config
    sudo chmod 644 /etc/stenographer/config
  fi
  sudo chown root:root /etc/stenographer
fi

if grep -q /path/to /etc/stenographer/config; then
  Error "Create directories to output packets/indexes to, then update"
  Error "/etc/stenographer/config to point to them."
  Error "Directories should be owned by stenographer:stenographer."
  exit 1
fi

sudo ./stenokeys.sh stenographer stenographer

Info "Copying stenographer/stenotype"
sudo cp -vf stenographer "$BINDIR/stenographer"
sudo chown stenographer:root "$BINDIR/stenographer"
sudo chmod 0700 "$BINDIR/stenographer"
sudo cp -vf stenotype/stenotype "$BINDIR/stenotype"
sudo chown stenographer:root "$BINDIR/stenotype"
sudo chmod 0500 "$BINDIR/stenotype"
SetCapabilities "$BINDIR/stenotype"

Info "Copying stenoread/stenocurl"
sudo cp -vf stenoread "$BINDIR/stenoread"
sudo chown root:root "$BINDIR/stenoread"
sudo chmod 0755 "$BINDIR/stenoread"
sudo cp -vf stenocurl "$BINDIR/stenocurl"
sudo chown root:root "$BINDIR/stenocurl"
sudo chmod 0755 "$BINDIR/stenocurl"

Info "Starting stenographer using upstart"
# If you're not using upstart, you can replace this with:
#   sudo -b -u stenographer $BINDIR/stenographer &
sudo service stenographer start

Info "Checking for running processes..."
sleep 5
if Running stenographer; then
  Info "  * Stenographer up and running"
else
  Error "  !!! Stenographer not running !!!"
  tail -n 100 /var/log/messages | grep steno
  exit 1
fi
if Running stenotype; then
  Info "  * Stenotype up and running"
else
  Error "  !!! Stenotype not running !!!"
  tail -n 100 /var/log/messages | grep steno
  exit 1
fi
