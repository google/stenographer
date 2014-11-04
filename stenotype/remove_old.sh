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

function PercentFull {
  df . | tail -n 1 | /usr/bin/awk '{print substr($5, 0, length($5)-1)}'
}

function OldestFile {
  for filename in $(ls -tr PKT$THREAD/); do
    filename="PKT$THREAD/$filename"
    if [ -f "$filename" ]; then
      echo "$filename"
      return
    fi
  done
}

cd "$1"
THREAD=$2

while [ $(PercentFull) -gt 90 ]; do
  filename="$(OldestFile)"
  rm -fv "${filename}"
  rm -fv "${filename//PKT/IDX}"
  sleep 1
done
