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

CFLAGS_SEC=-fPIC -fPIE -pie -fstack-protector -D_FORTIFY_SOURCE=2
CFLAGS=-std=c++0x -g -O2 -rdynamic -Wall -fno-strict-aliasing -I../ $(CFLAGS_SEC)
LDFLAGS_SEC=-Wl,-z,now -Wl,-z,relro
LDFLAGS=-lleveldb -lrt -laio -lpthread -lsnappy -lseccomp $(LDFLAGS_SEC)

all: index_bin_afl index_bin

fuzz:
	afl-fuzz -i tests -o findings ./index_bin_afl @@

clean:
	rm -f index_bin_afl index_bin

index_bin_afl: *.cc ../*.cc ../*.h
	afl-g++ $(CFLAGS) -o index_bin_afl index_bin.cc ../index.cc ../util.cc $(LDFLAGS)

index_bin: *.cc ../*.cc ../*.h
	g++ $(CFLAGS) -o index_bin index_bin.cc ../index.cc ../util.cc $(LDFLAGS)
