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

func parseIP(in string) net.IP {
	ip := net.ParseIP(in)
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return ip
}

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
func (q portQuery) String() string { return fmt.Sprintf("port=%d", q) }

type protocolQuery byte

func (q protocolQuery) LookupIn(ctx context.Context, index *indexfile.IndexFile) (bp base.Positions, err error) {
	defer log(q, index, &bp, &err)()
	return index.ProtoPositions(ctx, byte(q))
}
func (q protocolQuery) String() string { return fmt.Sprintf("protocol=%d", q) }

type ipQuery [2]net.IP

func (q ipQuery) LookupIn(ctx context.Context, index *indexfile.IndexFile) (bp base.Positions, err error) {
	defer log(q, index, &bp, &err)()
	return index.IPPositions(ctx, q[0], q[1])
}
func (q ipQuery) String() string { return fmt.Sprintf("ip=%v-%v", q[0], q[1]) }

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
	return strings.Join(all, "|")
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
	return strings.Join(all, " ")
}

type sinceQuery time.Time

func (a sinceQuery) LookupIn(ctx context.Context, index *indexfile.IndexFile) (bp base.Positions, err error) {
	defer log(a, index, &bp, &err)()
	last := filepath.Base(index.Name())
	intval, err := strconv.ParseInt(last, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("could not parse basename %q: %v", last, err)
	}
	t := time.Unix(0, intval*1000) // converts micros -> nanos
	if t.After(time.Time(a)) {
		v(2, "time query using %q", index.Name())
		return base.AllPositions, nil
	}
	v(2, "time query skipping %q", index.Name())
	return base.NoPositions, nil
}
func (a sinceQuery) String() string {
	return fmt.Sprintf("since=%v", time.Time(a))
}

func singleArgument(arg string) (Query, error) {
	parts := strings.Split(arg, "=")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid arg: %q", arg)
	}
	switch parts[0] {
	case "ip":
		ips := strings.Split(parts[1], "-")
		var from, to net.IP
		switch len(ips) {
		case 1:
			from = parseIP(ips[0])
			if from == nil {
				return nil, fmt.Errorf("invalid IP %v", ips[0])
			}
			to = from
		case 2:
			from = parseIP(ips[0])
			if from == nil {
				return nil, fmt.Errorf("invalid IP %v", ips[0])
			}
			to = parseIP(ips[1])
			if to == nil {
				return nil, fmt.Errorf("invalid IP %v", ips[1])
			}
			if len(from) != len(to) {
				return nil, fmt.Errorf("IP type mismatch: %v / %v", from, to)
			}
		default:
			return nil, fmt.Errorf("invalid #IPs: %q", arg)
		}
		return ipQuery{from, to}, nil
	case "port":
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %v", parts[1], err)
		}
		return portQuery(port), nil
	case "protocol":
		proto, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid proto %q: %v", parts[1], err)
		}
		return protocolQuery(proto), nil
	case "last":
		dur, err := time.ParseDuration(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid duration %q: %v", parts[1], err)
		} else if dur%time.Minute != 0 {
			return nil, fmt.Errorf("duration %q has high granularity, we support only 1m granularity", parts[1])
		}
		return sinceQuery(time.Now().Add(-dur)), nil
	default:
		return nil, fmt.Errorf("invalid query argument %q", arg)
	}
}

func unionArguments(arg string) (Query, error) {
	var union unionQuery
	for _, a := range strings.Split(arg, "|") {
		query, err := singleArgument(a)
		if err != nil {
			return nil, fmt.Errorf("error with union arg %q: %v", a, err)
		}
		union = append(union, query)
	}
	return union, nil
}

// NewQuery parses the given query arg and returns a query object.
// This query can then be passed into a blockfile to get out the set of packets
// which match it.
//
// Currently, we support one simple method of parsing a query, detailed in the
// README.md file.  Returns an error if the query string is invalid.
func NewQuery(query string) (Query, error) {
	var intersect intersectQuery
	for _, a := range strings.Fields(query) {
		query, err := unionArguments(a)
		if err != nil {
			return nil, fmt.Errorf("error with intersection arg %q: %v", a, err)
		}
		intersect = append(intersect, query)
	}
	return intersect, nil
}
