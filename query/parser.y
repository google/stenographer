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

%{
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
	"strconv"
	"net"
	"fmt"
	"strings"
	"unicode"
)

%}

%union {
	num int
	ip net.IP
	str string
	query Query
}

%type	<query>	top expr expr2

%token <str> HOST PORT PROTOCOL AND OR NET MASK TCP UDP ICMP
%token <ip> IP
%token <num> NUM

%%

top:
   expr
{
	parserlex.(*parserLex).out = $1
}

expr:
    expr2
|   expr AND expr2
{
	$$ = intersectQuery{$1, $3}
}
|   expr OR expr2
{
	$$ = unionQuery{$1, $3}
}

expr2:
    HOST IP
{
	$$ = ipQuery{$2, $2}
}
|   PORT NUM
{
	if $2 < 0 || $2 >= 65536 {
		parserlex.Error(fmt.Sprintf("invalid port %v", $2))
	}
	$$ = portQuery($2)
}
|   PROTOCOL NUM
{
	if $2 < 0 || $2 >= 256 {
		parserlex.Error(fmt.Sprintf("invalid protocol %v", $2))
	}
	$$ = protocolQuery($2)
}
|   NET IP '/' NUM
{
		mask := net.CIDRMask($4, len($2) * 8)
		if mask == nil {
			parserlex.Error(fmt.Sprintf("bad cidr: %v/%v", $2, $4))
		}
		from, to, err := ipsFromNet($2, mask)
		if err != nil {
			parserlex.Error(err.Error())
		}
		$$ = ipQuery{from, to}
}
|   NET IP MASK IP
{
		from, to, err := ipsFromNet($2, net.IPMask($4))
		if err != nil {
			parserlex.Error(err.Error())
		}
		$$ = ipQuery{from, to}
}
|   '(' expr ')'
{
	$$ = $2
}
|   TCP
{
	$$ = protocolQuery(6)
}
|   UDP
{
	$$ = protocolQuery(17)
}
|   ICMP
{
	$$ = protocolQuery(1)
}

%%

func ipsFromNet(ip net.IP, mask net.IPMask) (from, to net.IP, _ error) {
	if len(ip) != len(mask) || (len(ip) != 4 && len(ip) != 16) {
		return nil, nil, fmt.Errorf("bad IP or mask: %v %v", ip, mask)
	}
	from = make(net.IP, len(ip))
	to = make(net.IP, len(ip))
	for i := 0; i < len(ip); i++ {
		from[i] = ip[i] & mask[i]
		to[i] = ip[i] | ^mask[i]
	}
	return
}

// parserLex is used by the parser as a lexer.
// It must be named <prefix>Lex (where prefix is passed into go tool yacc with
// the -p flag).
type parserLex struct {
	in string
	pos int
	out Query
	err error
}

// tokens provides a simple map for adding new keywords and mapping them
// to token types.
var tokens = map[string]int{
 "host": HOST,
 "port": PORT,
 "protocol": PROTOCOL,
 "and": AND,
 "&&": AND,
 "or": OR,
 "||": OR,
 "net": NET,
 "mask": MASK,
 "tcp": TCP,
 "udp": UDP,
 "icmp": ICMP,
}

// Lex is called by the parser to get each new token.  This implementation
// is currently quite simplistic, but it seems to work pretty well for our
// needs.
//
// The type of the input argument must be *<prefix>SymType.
func (x *parserLex) Lex(yylval *parserSymType) (ret int) {
	for x.pos < len(x.in) && unicode.IsSpace(rune(x.in[x.pos])) {
		x.pos++
	}
	for t, i := range tokens {
		if strings.HasPrefix(x.in[x.pos:], t) {
			x.pos += len(t)
			return i
		}
	}
	s := x.pos
	var isIP bool
L:
	for x.pos < len(x.in) {
		switch c := x.in[x.pos]; c {
		case ':', '.':
			isIP = true
			x.pos++
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f':
			x.pos++
		default:
			break L
		}
	}
	if isIP {
		yylval.ip = net.ParseIP(x.in[s:x.pos])
		if yylval.ip == nil {
			x.Error(fmt.Sprintf("bad IP %q", x.in[s:x.pos]))
			return -1
		}
		if ip4 := yylval.ip.To4(); ip4 != nil {
			yylval.ip = ip4
		}
		return IP
	} else if x.pos != s {
		n, err := strconv.Atoi(x.in[s:x.pos])
		if err != nil { return -1 }
		yylval.num = n
		return NUM
	} else if x.pos >= len(x.in) {
		return 0
	}
	switch c := x.in[x.pos]; c {
	case ':', '.', '(', ')', '/':
		x.pos++
		return int(c)
	}
	return -1
}

// Error is called by the parser on a parse error.
func (x *parserLex) Error(s string) {
	if x.err == nil {
		x.err = fmt.Errorf("%v at character %v (%q HERE %q)", s, x.pos, x.in[:x.pos], x.in[x.pos:])
	}
}

// parse parses an input string into a Query.
func parse(in string) (Query, error) {
	lex := &parserLex{in: in}
	parserParse(lex)
	if lex.err != nil {
		return nil, lex.err
	}
	return lex.out, nil
}
