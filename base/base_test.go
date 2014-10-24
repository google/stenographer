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

package base

import (
	"reflect"
	"testing"
)

func TestUnion(t *testing.T) {
	for _, test := range []struct {
		a, b, want Int64Slice
	}{
		{
			Int64Slice{1, 2, 3},
			Int64Slice{2, 3, 4},
			Int64Slice{1, 2, 3, 4},
		},
		{
			Int64Slice{1, 2},
			Int64Slice{3, 4},
			Int64Slice{1, 2, 3, 4},
		},
		{
			Int64Slice{3, 4},
			Int64Slice{1, 2},
			Int64Slice{1, 2, 3, 4},
		},
	} {
		got := test.a.Union(test.b)
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("nope:\n   a: %v\n   b: %v\n got: %v\nwant: %v", test.a, test.b, got, test.want)
		}
	}
}
func Testintersect(t *testing.T) {
	for _, test := range []struct {
		a, b, want Int64Slice
	}{
		{
			Int64Slice{1, 2, 3, 4},
			Int64Slice{0, 2, 4, 5},
			Int64Slice{2, 4},
		},
		{
			Int64Slice{1, 2, 3},
			Int64Slice{2, 3, 4},
			Int64Slice{2, 3},
		},
		{
			Int64Slice{1, 2},
			Int64Slice{3, 4},
			Int64Slice{},
		},
		{
			Int64Slice{3, 4},
			Int64Slice{1, 2},
			Int64Slice{},
		},
	} {
		got := test.a.Intersect(test.b)
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("nope:\n   a: %v\n   b: %v\n got: %v\nwant: %v", test.a, test.b, got, test.want)
		}
	}
}
