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

# This script sets up stenographer keys for client/server auth.

set -e
if [[ $# != 3 ]]; then
  echo "USAGE: $0 <directory> <stenouser> <stenogroup>" >&2
  exit 1
fi
USR=$2
GRP=$3
cd $1
CONFIG=$(mktemp -t stenossl.XXXXXXXXXXXX)

function sslconfig_common {
cat <<EOF
[ req ]
default_md = sha256
prompt = no
distinguished_name = dn

[ dn ]
countryName = XX
organizationName = Stenographer
commonName = $1

EOF
}

function genca {
  if [ ! -f ca_cert.pem ]; then
    echo "Generating CA state"
    cat > ${CONFIG} <<EOF
$(sslconfig_common *.steno)
[ ca_ext ]
keyUsage = critical,keyCertSign,cRLSign
basicConstraints = critical,CA:true,pathlen:0
subjectKeyIdentifier = hash
EOF
    mkdir -p ca
    chmod 700 ca
    touch ca/index.txt
    if [ ! -f ca/serial ]; then
      echo 1000 > ca/serial
    fi
    openssl genrsa -out ca_key.pem 4096 2>>errs
    openssl req -new -x509 -config ${CONFIG} -extensions ca_ext -key ca_key.pem -out ca_cert.pem -days 9999 2>>errs
  else
    echo "Skipping CA state generation, ca_cert.pem already exists"
  fi
}

function server_common {
  STENOGRAPHER_CONFIG="${STENOGRAPHER_CONFIG-/etc/stenographer/config}"
  JQ="$(which jq)"
  HOST="$( < "$STENOGRAPHER_CONFIG" $JQ -r '.Host')"
  echo "$HOST"
}

function client_common {
  echo "client$(date +%s).steno"
}

function gencert {
  if [ -f ${1}_cert.pem ]; then
    echo "Skipping generation of '${1}' key/cert, ${1}_cert.pem already exists" >&2
  else
    echo "Generating key/cert for '${1}'"
    cat > ${CONFIG} <<EOF
$(sslconfig_common $(${1}_common))
[ client_ext ]
keyUsage = critical,digitalSignature
basicConstraints = CA:false
extendedKeyUsage = clientAuth

[ server_ext ]
keyUsage = critical,digitalSignature,keyEncipherment
basicConstraints = CA:false
extendedKeyUsage = serverAuth

[ ca_config ]
private_key = ca_key.pem
certificate = ca_cert.pem
new_certs_dir = ca
database = ca/index.txt
serial = ca/serial
default_md = default
default_days = 9999
policy = policy_match

[ policy_match ]
organizationName = match
countryName = match
commonName = supplied
EOF
    openssl genrsa -out ${1}_key.pem 4096 2>>errs
    openssl req -new -config ${CONFIG} -key ${1}_key.pem -out ${1}.csr -reqexts ${1}_ext -days 9999 2>>errs
    openssl ca -config ${CONFIG} -name ca_config -batch -out ${1}_cert.pem -infiles ${1}.csr 2>>errs
  fi
}

function ch {
  CHOWN=$1
  CHMOD=$2
  shift 2
  chown $CHOWN $@
  chmod $CHMOD $@
}

function onexit {
  if [ -f errs ]; then
    cat errs >&2
    rm -f errs
  fi
}

trap onexit EXIT

set -e

if [ ! -f ca_cert.pem ]; then
  # If we're upgrading an old instance of steno, without a CA cert, we'll need
  # to kill their existing certs/keys.
  rm -f {ca,client,server}_{cert,key}.pem
fi

genca
gencert client
gencert server

CURR_USR="$(id -u -n)"  # probably 'root'
CURR_GRP="$(id -g -n)"  # probably 'root'

ch $CURR_USR:$CURR_GRP 755 .
ch $CURR_USR:$CURR_GRP 400 ca_key.pem
ch $CURR_USR:$GRP      440 client_key.pem
ch $USR:$CURR_GRP      400 server_key.pem
ch $CURR_USR:$CURR_GRP 444 *_cert.pem

rm -f {client,server}.csr ${CONFIG} errs
