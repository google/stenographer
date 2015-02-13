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

SHARED_CFLAGS=-std=c++11 -g -Wall -fno-strict-aliasing
SHARED_LDFLAGS=-lleveldb -lrt -laio -lpthread -lsnappy -lseccomp

GCC=g++
GCC_CFLAGS_SEC=-fPIC -fPIE -pie -fstack-protector -D_FORTIFY_SOURCE=2
GCC_CFLAGS=-rdynamic -O2 $(GCC_CFLAGS_SEC)
GCC_LDFLAGS_SEC=-Wl,-z,now -Wl,-z,relro
GCC_LDFLAGS=$(GCC_LDFLAGS_SEC)

CLANG=clang++
CLANG_CFLAGS=-fno-omit-frame-pointer -O1 -fno-optimize-sibling-calls -fsanitize-memory-track-origins
CLANG_LDFLAGS=

FILES=util packets index aio stenotype

# We allow for the compiling of Clang binaries with -fsanitize=XXX by setting
# the SANITIZE argument.  If that argument is set, we'll build stenotype using
# Clang-specific flags.
# Examples:
#   make SANITIZE=address
#   make SANITIZE=memory
#   make SANITIZE=thread
# NOTE:  When clang is used, many security options are NOT.  Clang should be
# used just for testing, NOT for production systems.
SANITIZE=
ifndef SANITIZE
	OBJECTS=$(foreach file,$(FILES),$(file)_gcc.o)
	CFLAGS=$(SHARED_CFLAGS) $(GCC_CFLAGS)
	LDFLAGS=$(SHARED_LDFLAGS) $(GCC_LDFLAGS)
	CC=$(GCC)
else
	OBJECTS=$(foreach file,$(FILES),$(file)_$(SANITIZE)_clang.o)
	CFLAGS=$(SHARED_CFLAGS) $(CLANG_CFLAGS) -fsanitize=$(SANITIZE)
	LDFLAGS=$(SHARED_LDFLAGS) $(CLANG_LDFLAGS)
	CC=$(CLANG)
endif

all: stenotype

%_gcc.o: %.cc $(DEPS)
	$(GCC) $(GCC_CFLAGS) $(CFLAGS) -c -o $@ $<

%_$(SANITIZE)_clang.o: %.cc $(DEPS)
	$(CLANG) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o stenotype

stenotype: $(OBJECTS)
	$(CC) $(CFLAGS) -o stenotype $(OBJECTS) $(LDFLAGS)
