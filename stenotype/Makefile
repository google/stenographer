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

DEFINES=
ifneq (,$(wildcard /usr/include/testimony.h))
DEFINES += -DTESTIMONY
DEPS += /usr/include/testimony.h
endif

ifneq (,$(wildcard /usr/bin/c++))
CXX=/usr/bin/c++
endif
SHARED_CFLAGS=-std=c++0x -g -Wall -fno-strict-aliasing $(DEFINES)
SHARED_LDFLAGS=-lleveldb -lrt -laio -lpthread -lsnappy -lseccomp
ifneq (,$(wildcard /usr/include/testimony.h))
SHARED_LDFLAGS += -ltestimony
endif

OPT_CFLAGS_SEC=-fPIC -fPIE -fstack-protector -D_FORTIFY_SOURCE=2
OPT_CFLAGS=-O2 $(OPT_CFLAGS_SEC)
OPT_LDFLAGS_SEC=-Wl,-z,now -Wl,-z,relro
OPT_LDFLAGS=$(OPT_LDFLAGS_SEC)

DBG_CFLAGS=-fno-omit-frame-pointer -O1 -fno-optimize-sibling-calls
DBG_LDFLAGS=

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
# NOTE:  When sanitize is used, many security options are NOT.  Sanitize should
# be used just for testing, NOT for production systems.
SANITIZE=
ifndef SANITIZE
	OBJECTS=$(foreach file,$(FILES),$(file)_opt.o)
	CFLAGS=$(SHARED_CFLAGS) $(OPT_CFLAGS)
	LDFLAGS=$(SHARED_LDFLAGS) $(OPT_LDFLAGS)
else
	OBJECTS=$(foreach file,$(FILES),$(file)_$(SANITIZE)_dbg.o)
	CFLAGS=$(SHARED_CFLAGS) $(DBG_CFLAGS) -fsanitize=$(SANITIZE)
	LDFLAGS=$(SHARED_LDFLAGS) $(DBG_LDFLAGS)
	CXX=clang++ # Force clang if we're sanitizing
endif
ifeq "$(SANITIZE)" "memory"
	CFLAGS += -fsanitize-memory-track-origins
endif

all: stenotype

clean:
	rm -f *.o stenotype index_fuzz core


### Building stenotype, either in normal (g++) or sanitization (clang) modes ###

# Generate g++ object files.
%_opt.o: %.cc $(DEPS)
	$(CXX) $(CFLAGS) -c -o $@ $<

# Generate clang object files.
%_$(SANITIZE)_dbg.o: %.cc $(DEPS)
	$(CXX) $(CFLAGS) -c -o $@ $<

# Generate the stenotype binary itself.  You mostly want this :)
stenotype: $(OBJECTS)
	$(CXX) $(CFLAGS) -o $@ $^ $(LDFLAGS)



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

