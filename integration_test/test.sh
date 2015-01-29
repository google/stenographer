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

BASEDIR="${BASEDIR-/tmp}"
DUMMY="${DUMMY-dummy0}"
PORT="${PORT-9123}"
STRACE="$STRACE"  # Override to strace stenotype and stenographer
KEEPFILES="$KEEPFILES"  # Override to not delete files

set -e
cd $(dirname $0)
source ../lib.sh

function PullDownTestData {
  if [ ! -f $BASEDIR/steno_integration_test.pcap ]; then
    Info "Pulling down pcap data"
    # Test data pulled from
    # http://www.ll.mit.edu/mission/communications/cyber/CSTcorpora/ideval/data/2000/LLS_DDOS_1.0.html
    curl 'http://www.ll.mit.edu/mission/communications/cyber/CSTcorpora/ideval/data/2000/LLS_DDOS_1.0/data_and_labeling/tcpdump_inside/LLS_DDOS_1.0-inside.dump.gz' > $BASEDIR/steno_integration_test.pcap.gz
    gunzip $BASEDIR/steno_integration_test.pcap.gz
  fi
}

Info "Testing sudo access"
sudo cat /dev/null

InstallPackage tcpreplay

PullDownTestData

Info "Building stenographer"
pushd ../
go build
pushd stenotype
make
SetCapabilities stenotype
STENOTYPE_BIN="$(pwd)/stenotype"
popd
popd

Info "Setting up output directory"
OUTDIR="$(mktemp -d $BASEDIR/steno.XXXXXXXXXX)"
Info "Writing output to directory '$OUTDIR'"
LOG="${LOG-$OUTDIR/log}"
Info "Writing log to $LOG"

mkdir $OUTDIR/{pkt0,idx0,pkt1,idx1,pkt2,idx2,pkt3,idx3,certs}
Info "Setting up $DUMMY interface"
sudo /sbin/modprobe dummy
sudo ip link add dummy0 type dummy || Error "$DUMMY may already exist"
sudo ifconfig $DUMMY promisc up
set +e

function FailTest {
  Error "--- TEST FAILURE ---"
  Error "$@"
  exit 1
}

function TestCountPackets {
  FILTER="$1"
  WANT="$2"
  Info "Looking $WANT packets from filter '$FILTER'"
  GOT="$(STENOGRAPHER_CONFIG="$OUTDIR/config" ../stenoread "$FILTER" -n | wc -l)"
  if [ "$GOT" != "$WANT" ]; then
    FailTest "FAILED: Want: $WANT  Got: $GOT"
  fi
}

STENOGRAPHER_PID=""
STENOTYPE_PID=""
function CleanUp {
  Info "Cleaning up"
  if [ ! -z "$STENOGRAPHER_PID" ]; then
    Info "Killing stenographer ($STENOGRAPHER_PID)"
    KILLCMD=kill ReallyKill $STENOGRAPHER_PID
  fi
  if [ ! -z "$STENOTYPE_PID" ]; then
    Info "Killing stenotype ($STENOTYPE_PID)"
    KILLCMD=kill ReallyKill $STENOTYPE_PID
  fi
  Info "Deleting $DUMMY interface"
  if [ -z "$KEEPFILES" ]; then
    Info "Removing $OUTDIR"
    rm -rfv $OUTDIR
  fi
  sudo ifconfig $DUMMY down
  sudo ip link del dummy0
}
trap CleanUp EXIT

cat > $OUTDIR/config << EOF
{
  "Threads": [
    { "PacketsDirectory": "$OUTDIR/pkt0" , "IndexDirectory": "$OUTDIR/idx0", "DiskFreePercentage": 1 }
  , { "PacketsDirectory": "$OUTDIR/pkt1" , "IndexDirectory": "$OUTDIR/idx1", "DiskFreePercentage": 1 }
  , { "PacketsDirectory": "$OUTDIR/pkt2" , "IndexDirectory": "$OUTDIR/idx2", "DiskFreePercentage": 1 }
  , { "PacketsDirectory": "$OUTDIR/pkt3" , "IndexDirectory": "$OUTDIR/idx3", "DiskFreePercentage": 1 }
  ]
  , "StenotypePath": "$STENOTYPE_BIN"
  , "Interface": "$DUMMY"
  , "Port": $PORT
  , "Flags": ["--v=8"]
  , "CertPath": "$OUTDIR/certs"
}
EOF
Info "Starting stenographer"
../stenographer --config=$OUTDIR/config --syslog=false --v=4 >$LOG 2>&1 &
STENOGRAPHER_PID="$!"
if [ ! -z "$STRACE" ]; then
  sudo -b strace -f -o $STRACE -p $STENOGRAPHER_PID &
fi

Info "Waiting for stenographer to start up"
Sleep 5

STENOTYPE_PID="$(ps axww |
    grep -v grep |
    grep -v Z |
    grep $STENOTYPE_BIN |
    awk '{print $1}')"
if [ -z "$STENOTYPE_PID" ]; then
  FailTest "Stenotype not running"
fi
function CheckStillRunning {
  if ! kill -0 $STENOTYPE_PID; then
    FailTest "stenotype has stopped!"
  fi
  if ! kill -0 $STENOGRAPHER_PID; then
    FailTest "stenographer has stopped!"
  fi
  Info "All processes still running"
}

Info "Sending packets to $DUMMY"
sudo tcpreplay -i $DUMMY --topspeed $BASEDIR/steno_integration_test.pcap
Sleep 80
CheckStillRunning

Info "Looking for packets"
TestCountPackets "port 21582" 1018
TestCountPackets "host 0.100.194.86" 2
TestCountPackets "net 0.0.0.0/8" 580
TestCountPackets "net 172.0.0.0/8 and port 23" 292041

Info "Sending packets to $DUMMY a second time"
sudo tcpreplay -i $DUMMY --topspeed $BASEDIR/steno_integration_test.pcap
Sleep 80
CheckStillRunning

Info "Looking for packets a second time, in parallel"
TESTPIDS=""
TestCountPackets "port 21582" 2036 &
TESTPIDS="$TESTPIDS $!"
TestCountPackets "host 0.100.194.86" 4 &
TESTPIDS="$TESTPIDS $!"
TestCountPackets "net 0.0.0.0/8" 1160 &
TESTPIDS="$TESTPIDS $!"
TestCountPackets "net 172.0.0.0/8 and port 23" 584082 &
TESTPIDS="$TESTPIDS $!"
wait $TESTPIDS

Info "Done"
