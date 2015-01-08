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

//go:generate go tool yacc -p parser parser.y
//go:generate go fmt y.go

// Package query provides objects for specifying a query against stenographer.
package query

import (
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/stenographer/base"
	"github.com/google/stenographer/indexfile"
	"golang.org/x/net/context"
)

var v = base.V // verbose logging.

// Query encodes the set of packets a requester wants to get from stenographer.
type Query interface {
	// LookupIn finds the set of packet positions for all packets that match the
	// query from an index file.  Users shouldn't call this directly, and should
	// instead pass the query into BlockFile's Lookup() to get back actual
	// packets.
	LookupIn(context.Context, *indexfile.IndexFile) (base.Positions, error)
	// String returns a human readable string for this query.
	String() string
}

func log(q Query, i *indexfile.IndexFile, bp *base.Positions, err *error) func() {
	start := time.Now()
	return func() {
		v(3, "Query %q in %q took %v, found %d  %v", q, i.Name(), time.Since(start), len(*bp), *err)
	}
}

type portQuery uint16

func (q portQuery) LookupIn(ctx context.Context, index *indexfile.IndexFile) (bp base.Positions, err error) {
	defer log(q, index, &bp, &err)()
	return index.PortPositions(ctx, uint16(q))
}
func (q portQuery) String() string { return fmt.Sprintf("port %d", q) }

type protocolQuery byte

func (q protocolQuery) LookupIn(ctx context.Context, index *indexfile.IndexFile) (bp base.Positions, err error) {
	defer log(q, index, &bp, &err)()
	return index.ProtoPositions(ctx, byte(q))
}
func (q protocolQuery) String() string { return fmt.Sprintf("protocol %d", q) }

type ipQuery [2]net.IP

func (q ipQuery) LookupIn(ctx context.Context, index *indexfile.IndexFile) (bp base.Positions, err error) {
	defer log(q, index, &bp, &err)()
	return index.IPPositions(ctx, q[0], q[1])
}
func (q ipQuery) String() string { return fmt.Sprintf("host %v-%v", q[0], q[1]) }

type unionQuery []Query

func (a unionQuery) LookupIn(ctx context.Context, index *indexfile.IndexFile) (bp base.Positions, err error) {
	defer log(a, index, &bp, &err)()
	var positions base.Positions
	for _, query := range a {
		pos, err := query.LookupIn(ctx, index)
		if err != nil {
			return nil, err
		}
		positions = positions.Union(pos)
	}
	return positions, nil
}
func (q unionQuery) String() string {
	all := make([]string, len(q))
	for i, query := range q {
		all[i] = query.String()
	}
	return "(" + strings.Join(all, " or ") + ")"
}

type intersectQuery []Query

func (a intersectQuery) LookupIn(ctx context.Context, index *indexfile.IndexFile) (bp base.Positions, err error) {
	defer log(a, index, &bp, &err)()
	positions := base.AllPositions
	for _, query := range a {
		pos, err := query.LookupIn(ctx, index)
		if err != nil {
			return nil, err
		}
		positions = positions.Intersect(pos)
	}
	return positions, nil
}
func (q intersectQuery) String() string {
	all := make([]string, len(q))
	for i, query := range q {
		all[i] = query.String()
	}
	return "(" + strings.Join(all, " and ") + ")"
}

type timeQuery [2]time.Time

func (a timeQuery) LookupIn(ctx context.Context, index *indexfile.IndexFile) (bp base.Positions, err error) {
	defer log(a, index, &bp, &err)()
	last := filepath.Base(index.Name())
	intval, err := strconv.ParseInt(last, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("could not parse basename %q: %v", last, err)
	}
	t := time.Unix(0, intval*1000) // converts micros -> nanos
	if !a[0].IsZero() && t.Before(a[0]) {
		v(2, "time query skipping %q", index.Name())
		return base.NoPositions, nil
	}
	if !a[1].IsZero() && t.After(a[1]) {
		v(2, "time query skipping %q", index.Name())
		return base.NoPositions, nil
	}
	v(2, "time query using %q", index.Name())
	return base.AllPositions, nil
}
func (a timeQuery) String() string {
	if a[0].IsZero() {
		return fmt.Sprintf("before %v", a[1].Format(time.RFC3339))
	}
	return fmt.Sprintf("after %v", a[0].Format(time.RFC3339))
}

// NewQuery parses the given query arg and returns a query object.
// This query can then be passed into a blockfile to get out the set of packets
// which match it.
//
// Currently, we support one simple method of parsing a query, detailed in the
// README.md file.  Returns an error if the query string is invalid.
func NewQuery(query string) (Query, error) {
	return parse(query)
}
