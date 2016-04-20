#!/usr/bin/env bash
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
#
# stenographer - full packet to disk capture
#
# stenographer is a simple, fast method of writing live packets to disk,
# then requesting those packets after-the-fact for post-hoc analysis.

#===============================================================#
# Installs Stenographer on CentOS 7.1
#===============================================================#

export KILLCMD=/usr/bin/pkill
export BINDIR="${BINDIR-/usr/bin}"
export GOPATH=${HOME}/go
export PATH=${PATH}:/usr/local/go/bin


# Load support functions
_scriptDir="$(dirname `readlink -f $0`)"
source lib.sh

check_sudo () {
	Info "Checking for sudo...  "
	if (! sudo cat /dev/null); then
		Error "Failed. Please configure sudo support for this user."
		exit 1;
	fi
}

stop_processes () {
	Info "Killing any already running processes..."
	sudo service stenographer stop
	ReallyKill stenographer
	ReallyKill stenotype
}

install_packages () {
	Info "Installing stenographer package requirements...  "
	sudo yum install -y epel-release; sudo yum makecache
	sudo yum install -y libaio-devel leveldb-devel snappy-devel gcc-c++ make libcap-devel libseccomp-devel &>/dev/null

	if [ $? -ne 0 ]; then
		Error "Error. Please check that yum can install needed packages."
		exit 2;
	fi
}

install_golang () {
	local _url="https://storage.googleapis.com/golang/go1.4.2.linux-amd64.tar.gz"

	if (! which go &>/dev/null ); then
		Info "Installing golang ..."
		curl -L -O -J -s $_url
		sudo tar -C /usr/local -zxf $(basename $_url)
		sudo tee /etc/profile.d/golang.sh >/dev/null << EOF
pathmunge /usr/local/go/bin
export GOPATH=\${HOME}/go
EOF
	fi

}

# Install jq, if not present
install_jq () {
	local _url="https://github.com/stedolan/jq/releases/download/jq-1.5rc2/jq-linux-x86_64"
	if (! which jq &>/dev/null); then 
		Info "Installing jq ..."
		curl -s -L -J $_url | sudo tee /usr/local/bin/jq >/dev/null;
		sudo chmod +x /usr/local/bin/jq; 
	fi
}

add_accounts () {
	if ! id stenographer &>/dev/null; then
		Info "Setting up stenographer user"
		sudo adduser --system --no-create-home stenographer
	fi
	if ! getent group stenographer &>/dev/null; then
		Info "Setting up stenographer group"
		sudo addgroup --system stenographer
	fi
}

install_configs () {
	cd $_scriptDir

	Info "Setting up stenographer conf directory"
	if [ ! -d /etc/stenographer/certs ]; then
		sudo mkdir -p /etc/stenographer/certs
		sudo chown -R root:root /etc/stenographer/certs
	fi
	if [ ! -f /etc/stenographer/config ]; then
		sudo cp -vf configs/steno.conf /etc/stenographer/config
		sudo chown root:root /etc/stenographer/config
		sudo chmod 644 /etc/stenographer/config
	fi
	sudo chown root:root /etc/stenographer

	if grep -q /path/to /etc/stenographer/config; then
		Error "Create output directories for packets/index, then update"
		Error "/etc/stenographer/config"
		exit 1
	fi
}

install_certs () {
	cd $_scriptDir
    sudo ./stenokeys.sh stenographer stenographer
}

install_service () {
	cd $_scriptDir

	if [ ! -f /etc/security/limits.d/stenographer.conf ]; then
		Info "Setting up stenographer limits"
		sudo cp -v configs/limits.conf /etc/security/limits.d/stenographer.conf
	fi

	if [ ! -f /etc/systemd/system/stenographer.service ]; then
		Info "Installing stenographer systemd service"
		sudo cp -v configs/systemd.conf /etc/systemd/system/stenographer.service
		sudo chmod 0644 /etc/systemd/system/stenographer.service
	fi
}

build_stenographer () {

	if [ ! -x "$BINDIR/stenographer" ]; then
		Info "Building/Installing stenographer"
		/usr/local/go/bin/go get ./...
		/usr/local/go/bin/go build
		sudo cp -vf stenographer "$BINDIR/stenographer"
		sudo chown stenographer:root "$BINDIR/stenographer"
		sudo chmod 700 "$BINDIR/stenographer"
	else
		Info "stenographer already exists at $BINDIR/stenographer. Skipping"
	fi
}

build_stenotype () {
	cd ${_scriptDir}
	if [ ! -x "$BINDIR/stenotype" ]; then
		Info "Building/Installing stenotype"
		pushd ${_scriptDir}/stenotype
		make
		popd
		sudo cp -vf stenotype/stenotype "$BINDIR/stenotype"
		sudo chown stenographer:root "$BINDIR/stenotype"
		sudo chmod 0500 "$BINDIR/stenotype"
		SetCapabilities "$BINDIR/stenotype"
	else
		Info "stenotype already exists at $BINDIR/stenotype. Skipping"
	fi		
}

install_stenoread () {
	Info "Installing stenoread/stenocurl"
	sudo cp -vf stenoread "$BINDIR/stenoread"
	sudo chown root:root "$BINDIR/stenoread"
	sudo chmod 0755 "$BINDIR/stenoread"
	sudo cp -vf stenocurl "$BINDIR/stenocurl"
	sudo chown root:root "$BINDIR/stenocurl"
	sudo chmod 0755 "$BINDIR/stenocurl"
}

start_service () {
	Info "Starting stenographer service"
	sudo service stenographer start

	Info "Checking for running processes..."
	sleep 5
	if Running stenographer; then
	  Info "  * Stenographer up and running"
	else
	  Error "  !!! Stenographer not running !!!"
	  sudo tail -n 100 /var/log/messages | grep steno
	  exit 1
	fi
	if Running stenotype; then
	  Info "  * Stenotype up and running"
	else
	  Error "  !!! Stenotype not running !!!"
	  sudo tail -n 100 /var/log/messages | grep steno
	  exit 1
	fi
}

check_sudo
install_packages
install_golang
add_accounts
build_stenographer
build_stenotype
install_jq
install_configs
install_certs
install_service
install_stenoread
stop_processes
start_service
