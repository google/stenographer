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

DUMMY="${DUMMY-dummy0}"
PORT="${PORT-9123}"
BASEDIR="${BASEDIR-/tmp}"
SKIP_CLEANUP="${SKIP_CLEANUP}"

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

function TestCountPackets {
  FILTER="$1"
  WANT="$2"
  Info "Looking $WANT packets from filter '$FILTER'"
  GOT="$(STENOGRAPHER_CONFIG="$OUTDIR/config" ../stenoread "$FILTER" -n | wc -l)"
  if [ "$GOT" != "$WANT" ]; then
    Error " - FAILED for filter '$FILTER': Want: $WANT  Got: $GOT"
    exit 1
  else
    Info " - SUCCESS: Got $GOT packets from filter '$FILTER'"
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

mkdir $OUTDIR/{pkt,idx,certs}
Info "Setting up $DUMMY interface"
sudo /sbin/modprobe dummy
sudo ip link add dummy0 type dummy || Error "$DUMMY may already exist"
sudo ifconfig $DUMMY promisc up
set +e

STENOGRAPHER_PID=""
STENOTYPE_PID=""
function CleanUp {
  if [ -z "$SKIP_CLEANUP" ]; then
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
    Info "Removing $OUTDIR"
    rm -rfv $OUTDIR
    sudo ifconfig $DUMMY down
    sudo ip link del dummy0
  fi
}
trap CleanUp EXIT

cat > $OUTDIR/config << EOF
{
  "Threads": [
    { "PacketsDirectory": "$OUTDIR/pkt"
    , "IndexDirectory": "$OUTDIR/idx"
    , "DiskFreePercentage": 1
    }
  ]
  , "StenotypePath": "$STENOTYPE_BIN"
  , "Interface": "$DUMMY"
  , "Port": $PORT
  , "Flags": ["-v", "-v", "-v"]
  , "CertPath": "$OUTDIR/certs"
}
EOF
Info "Starting stenographer"
../stenographer --config=$OUTDIR/config --syslog=false --v=4 >$OUTDIR/log 2>&1 &
STENOGRAPHER_PID="$!"

xterm -e "tail -f $OUTDIR/log" &

Info "Waiting for stenographer to start up"
Sleep 15
STENOTYPE_PID="$(ps axww |
    grep -v grep |
    grep -v Z |
    grep $STENOTYPE_BIN |
    awk '{print $1}')"
if [ -z "$STENOTYPE_PID" ]; then
  Error "Stenotype not running"
  exit 1
fi

Info "Sending packets to $DUMMY"
sudo tcpreplay -i $DUMMY --topspeed $BASEDIR/steno_integration_test.pcap
Sleep 80

Info "Looking for packets"
TestCountPackets "port 21582" 1018
TestCountPackets "host 0.100.194.86" 2
TestCountPackets "net 0.0.0.0/8" 580
TestCountPackets "net 172.0.0.0/8 and port 23" 292041

Info "Sending packets to $DUMMY a second time"
sudo tcpreplay -i $DUMMY --topspeed $BASEDIR/steno_integration_test.pcap
Sleep 80

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
