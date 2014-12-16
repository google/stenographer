// Copyright 2014 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package query

import (
	"testing"
)

func TestParsingValidQueries(t *testing.T) {
	for _, test := range []string{
		"ip=1.2.3.4",
		"ip=1.1.1.1|ip=2.2.2.2",
		"ip=1.1.1.1 port=234 protocol=7",
		"port=123|port=456 ip=1::1 ip=2::2-2::8",
		"port=1    port=2 \t port=4",
	} {
		if _, err := NewQuery(test); err != nil {
			t.Fatalf("could not parse valid query %q: %v", test, err)
		}
	}
}

func TestParsingInvalidQuery(t *testing.T) {
	for _, test := range []string{
		"ip=1.1.1",
		"port=1.2.3.4",
		"port=1-6",
		"foo",
		"ip=1.2.3.4-1::8",
	} {
		if q, err := NewQuery(test); err == nil {
			t.Fatalf("parsed invalid query %q: %v", test, q)
		}
	}
}
