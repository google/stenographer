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
}

type portQuery uint16

func (q portQuery) LookupIn(ctx context.Context, index *indexfile.IndexFile) (base.Positions, error) {
	return index.PortPositions(ctx, uint16(q))
}

type protocolQuery byte

func (q protocolQuery) LookupIn(ctx context.Context, index *indexfile.IndexFile) (base.Positions, error) {
	return index.ProtoPositions(ctx, byte(q))
}

type ipQuery [2]net.IP

func (q ipQuery) LookupIn(ctx context.Context, index *indexfile.IndexFile) (base.Positions, error) {
	return index.IPPositions(ctx, q[0], q[1])
}

type unionQuery []Query

func (a unionQuery) LookupIn(ctx context.Context, index *indexfile.IndexFile) (base.Positions, error) {
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

type intersectQuery []Query

func (a intersectQuery) LookupIn(ctx context.Context, index *indexfile.IndexFile) (base.Positions, error) {
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

type sinceQuery time.Time

func (a sinceQuery) LookupIn(ctx context.Context, index *indexfile.IndexFile) (base.Positions, error) {
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

func singleArgument(arg string) (Query, error) {
	parts := strings.Split(arg, "=")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid arg: %q", arg)
	}
	var err error
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
		default:
			return nil, fmt.Errorf("invalid #IPs: %q", arg)
		}
		return ipQuery{from, to}, nil
	case "port":
		port, perr := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %v", parts[1], perr)
		}
		return portQuery(port), nil
	case "protocol":
		proto, perr := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid proto %q: %v", parts[1], perr)
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
		query, err := singleArgument(a)
		if err != nil {
			return nil, fmt.Errorf("error with intersection arg %q: %v", a, err)
		}
		intersect = append(intersect, query)
	}
	return intersect, nil
}
