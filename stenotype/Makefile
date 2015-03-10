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

DEPS=Makefile *.h

SHARED_CFLAGS=-std=c++0x -g -Wall -fno-strict-aliasing
SHARED_LDFLAGS=-lleveldb -lrt -laio -lpthread -lsnappy -lseccomp -ltestimony

GCC=g++
GCC_CFLAGS_SEC=-fPIC -fPIE -pie -fstack-protector -D_FORTIFY_SOURCE=2
GCC_CFLAGS=-rdynamic -O2 $(GCC_CFLAGS_SEC)
GCC_LDFLAGS_SEC=-Wl,-z,now -Wl,-z,relro
GCC_LDFLAGS=$(GCC_LDFLAGS_SEC)

CLANG=clang++
CLANG_CFLAGS=-fno-omit-frame-pointer -O1 -fno-optimize-sibling-calls
CLANG_LDFLAGS=

FILES=util packets index aio stenotype

AFL=afl-g++
FUZZ_FILES=util index index_bin

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
ifeq "$(SANITIZE)" "memory"
	CFLAGS += -fsanitize-memory-track-origins
endif

all: stenotype

clean:
	rm -f *.o stenotype index_fuzz core



### Building stenotype, either in normal (g++) or sanitization (clang) modes ###

# Generate g++ object files.
%_gcc.o: %.cc $(DEPS)
	$(GCC) $(CFLAGS) -c -o $@ $<

# Generate clang object files.
%_$(SANITIZE)_clang.o: %.cc $(DEPS)
	$(CLANG) $(CFLAGS) -c -o $@ $<

# Generate the stenotype binary itself.  You mostly want this :)
stenotype: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)



### Fuzzing with AFL ###

# Generate afl object files.
%_afl.o: %.cc $(DEPS)
	$(AFL) $(SHARED_CFLAGS) -c -o $@ $<

# Generate binary for afl fuzzing, which exercises the indexing code path.
index_fuzz: $(foreach file,$(FUZZ_FILES),$(file)_afl.o)
	$(AFL) $(SHARED_CFLAGS) -o index_fuzz $^ $(SHARED_LDFLAGS)

# Run afl-fuzz to fuzz the index_fuzz binary.
fuzz: index_fuzz
	afl-fuzz -i afl_tests -o afl_findings ./index_fuzz @@

