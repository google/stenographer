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

CC=g++
CFLAGS_SEC=-fPIE -pie -fstack-protector -D_FORTIFY_SOURCE=2
CFLAGS=-std=c++0x -g -O2 -rdynamic -Wall $(CFLAGS_SEC)
LDFLAGS_SEC=-Wl,-z,now -Wl,-z,relro
LDFLAGS=-lleveldb -lrt -laio -lpthread -lsnappy -lseccomp $(LDFLAGS_SEC)

all: stenotype

%.o: %.cc $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o stenotype

stenotype: util.o packets.o index.o aio.o stenotype.o
	$(CC) $(CFLAGS) -o stenotype *.o $(LDFLAGS)
