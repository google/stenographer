//line parser.y:16

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

import __yyfmt__ "fmt"

//line parser.y:30
import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
)

//line parser.y:43
type parserSymType struct {
	yys   int
	num   int
	ip    net.IP
	str   string
	query Query
	dur   time.Duration
	time  time.Time
}

const HOST = 57346
const PORT = 57347
const PROTO = 57348
const AND = 57349
const OR = 57350
const NET = 57351
const MASK = 57352
const TCP = 57353
const UDP = 57354
const ICMP = 57355
const BEFORE = 57356
const AFTER = 57357
const IPP = 57358
const AGO = 57359
const VLAN = 57360
const MPLS = 57361
const IP = 57362
const NUM = 57363
const DURATION = 57364
const TIME = 57365

var parserToknames = []string{
	"HOST",
	"PORT",
	"PROTO",
	"AND",
	"OR",
	"NET",
	"MASK",
	"TCP",
	"UDP",
	"ICMP",
	"BEFORE",
	"AFTER",
	"IPP",
	"AGO",
	"VLAN",
	"MPLS",
	"IP",
	"NUM",
	"DURATION",
	"TIME",
}
var parserStatenames = []string{}

const parserEofCode = 1
const parserErrCode = 2
const parserMaxDepth = 200

//line parser.y:172
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
	now time.Time // guarantees consistent time differences
	in  string
	pos int
	out Query
	err error
}

// tokens provides a simple map for adding new keywords and mapping them
// to token types.
var tokens = map[string]int{
	"after":  AFTER,
	"ago":    AGO,
	"&&":     AND,
	"and":    AND,
	"before": BEFORE,
	"host":   HOST,
	"icmp":   ICMP,
	"ip":     IPP,
	"mask":   MASK,
	"net":    NET,
	"||":     OR,
	"or":     OR,
	"port":   PORT,
	"vlan":   VLAN,
	"mpls":   MPLS,
	"proto":  PROTO,
	"tcp":    TCP,
	"udp":    UDP,
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
	var isIP, isDuration, isTime bool
L:
	for x.pos < len(x.in) {
		switch c := x.in[x.pos]; c {
		case ':', '.':
			isIP = true
			x.pos++
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f':
			x.pos++
		case 'm', 'h':
			x.pos++
			isDuration = true
			break L
		case '-', 'T', '+', 'Z':
			x.pos++
			isTime = true
		default:
			break L
		}
	}
	part := x.in[s:x.pos]
	switch {
	case isTime:
		t, err := time.Parse(time.RFC3339, part)
		if err != nil {
			x.Error(fmt.Sprintf("bad time %q", part))
		}
		yylval.time = t
		return TIME
	case isIP:
		yylval.ip = net.ParseIP(part)
		if yylval.ip == nil {
			x.Error(fmt.Sprintf("bad IP %q", part))
			return -1
		}
		if ip4 := yylval.ip.To4(); ip4 != nil {
			yylval.ip = ip4
		}
		return IP
	case isDuration:
		duration, err := time.ParseDuration(part)
		if err != nil {
			x.Error(fmt.Sprintf("bad duration %q", part))
		}
		yylval.dur = duration
		return DURATION
	case x.pos != s:
		n, err := strconv.Atoi(part)
		if err != nil {
			return -1
		}
		yylval.num = n
		return NUM
	case x.pos >= len(x.in):
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
	lex := &parserLex{in: in, now: time.Now()}
	parserParse(lex)
	if lex.err != nil {
		return nil, lex.err
	}
	return lex.out, nil
}

//line yacctab:1
var parserExca = []int{
	-1, 1,
	1, -1,
	-2, 0,
}

const parserNprod = 20
const parserPrivate = 57344

var parserTokenNames []string
var parserStates []string

const parserLast = 46

var parserAct = []int{

	4, 5, 27, 26, 33, 9, 36, 11, 12, 13,
	14, 15, 8, 31, 6, 7, 16, 17, 32, 21,
	20, 10, 19, 37, 23, 18, 3, 35, 2, 25,
	16, 17, 22, 1, 0, 34, 0, 0, 0, 24,
	0, 0, 0, 29, 30, 28,
}
var parserPact = []int{

	-4, -1000, 23, -1000, 5, 1, -1, -2, 26, 4,
	-4, -1000, -1000, -1000, -20, -20, -4, -4, -1000, -1000,
	-1000, -1000, -8, -6, 9, -1000, -1000, 10, -1000, -1000,
	-1000, -1000, -15, 3, -1000, -1000, -1000, -1000,
}
var parserPgo = []int{

	0, 33, 28, 26, 29,
}
var parserR1 = []int{

	0, 1, 2, 2, 2, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 4, 4,
}
var parserR2 = []int{

	0, 1, 1, 3, 3, 2, 2, 2, 2, 3,
	4, 4, 3, 1, 1, 1, 2, 2, 1, 2,
}
var parserChk = []int{

	-1000, -1, -2, -3, 4, 5, 18, 19, 16, 9,
	25, 11, 12, 13, 14, 15, 7, 8, 20, 21,
	21, 21, 6, 20, -2, -4, 23, 22, -4, -3,
	-3, 21, 24, 10, 26, 17, 21, 20,
}
var parserDef = []int{

	0, -2, 1, 2, 0, 0, 0, 0, 0, 0,
	0, 13, 14, 15, 0, 0, 0, 0, 5, 6,
	7, 8, 0, 0, 0, 16, 18, 0, 17, 3,
	4, 9, 0, 0, 12, 19, 10, 11,
}
var parserTok1 = []int{

	1, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	25, 26, 3, 3, 3, 3, 3, 24,
}
var parserTok2 = []int{

	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
	22, 23,
}
var parserTok3 = []int{
	0,
}

//line yaccpar:1

/*	parser for yacc output	*/

var parserDebug = 0

type parserLexer interface {
	Lex(lval *parserSymType) int
	Error(s string)
}

const parserFlag = -1000

func parserTokname(c int) string {
	// 4 is TOKSTART above
	if c >= 4 && c-4 < len(parserToknames) {
		if parserToknames[c-4] != "" {
			return parserToknames[c-4]
		}
	}
	return __yyfmt__.Sprintf("tok-%v", c)
}

func parserStatname(s int) string {
	if s >= 0 && s < len(parserStatenames) {
		if parserStatenames[s] != "" {
			return parserStatenames[s]
		}
	}
	return __yyfmt__.Sprintf("state-%v", s)
}

func parserlex1(lex parserLexer, lval *parserSymType) int {
	c := 0
	char := lex.Lex(lval)
	if char <= 0 {
		c = parserTok1[0]
		goto out
	}
	if char < len(parserTok1) {
		c = parserTok1[char]
		goto out
	}
	if char >= parserPrivate {
		if char < parserPrivate+len(parserTok2) {
			c = parserTok2[char-parserPrivate]
			goto out
		}
	}
	for i := 0; i < len(parserTok3); i += 2 {
		c = parserTok3[i+0]
		if c == char {
			c = parserTok3[i+1]
			goto out
		}
	}

out:
	if c == 0 {
		c = parserTok2[1] /* unknown char */
	}
	if parserDebug >= 3 {
		__yyfmt__.Printf("lex %s(%d)\n", parserTokname(c), uint(char))
	}
	return c
}

func parserParse(parserlex parserLexer) int {
	var parsern int
	var parserlval parserSymType
	var parserVAL parserSymType
	parserS := make([]parserSymType, parserMaxDepth)

	Nerrs := 0   /* number of errors */
	Errflag := 0 /* error recovery flag */
	parserstate := 0
	parserchar := -1
	parserp := -1
	goto parserstack

ret0:
	return 0

ret1:
	return 1

parserstack:
	/* put a state and value onto the stack */
	if parserDebug >= 4 {
		__yyfmt__.Printf("char %v in %v\n", parserTokname(parserchar), parserStatname(parserstate))
	}

	parserp++
	if parserp >= len(parserS) {
		nyys := make([]parserSymType, len(parserS)*2)
		copy(nyys, parserS)
		parserS = nyys
	}
	parserS[parserp] = parserVAL
	parserS[parserp].yys = parserstate

parsernewstate:
	parsern = parserPact[parserstate]
	if parsern <= parserFlag {
		goto parserdefault /* simple state */
	}
	if parserchar < 0 {
		parserchar = parserlex1(parserlex, &parserlval)
	}
	parsern += parserchar
	if parsern < 0 || parsern >= parserLast {
		goto parserdefault
	}
	parsern = parserAct[parsern]
	if parserChk[parsern] == parserchar { /* valid shift */
		parserchar = -1
		parserVAL = parserlval
		parserstate = parsern
		if Errflag > 0 {
			Errflag--
		}
		goto parserstack
	}

parserdefault:
	/* default state action */
	parsern = parserDef[parserstate]
	if parsern == -2 {
		if parserchar < 0 {
			parserchar = parserlex1(parserlex, &parserlval)
		}

		/* look through exception table */
		xi := 0
		for {
			if parserExca[xi+0] == -1 && parserExca[xi+1] == parserstate {
				break
			}
			xi += 2
		}
		for xi += 2; ; xi += 2 {
			parsern = parserExca[xi+0]
			if parsern < 0 || parsern == parserchar {
				break
			}
		}
		parsern = parserExca[xi+1]
		if parsern < 0 {
			goto ret0
		}
	}
	if parsern == 0 {
		/* error ... attempt to resume parsing */
		switch Errflag {
		case 0: /* brand new error */
			parserlex.Error("syntax error")
			Nerrs++
			if parserDebug >= 1 {
				__yyfmt__.Printf("%s", parserStatname(parserstate))
				__yyfmt__.Printf(" saw %s\n", parserTokname(parserchar))
			}
			fallthrough

		case 1, 2: /* incompletely recovered error ... try again */
			Errflag = 3

			/* find a state where "error" is a legal shift action */
			for parserp >= 0 {
				parsern = parserPact[parserS[parserp].yys] + parserErrCode
				if parsern >= 0 && parsern < parserLast {
					parserstate = parserAct[parsern] /* simulate a shift of "error" */
					if parserChk[parserstate] == parserErrCode {
						goto parserstack
					}
				}

				/* the current p has no shift on "error", pop stack */
				if parserDebug >= 2 {
					__yyfmt__.Printf("error recovery pops state %d\n", parserS[parserp].yys)
				}
				parserp--
			}
			/* there is no state on the stack with an error shift ... abort */
			goto ret1

		case 3: /* no shift yet; clobber input char */
			if parserDebug >= 2 {
				__yyfmt__.Printf("error recovery discards %s\n", parserTokname(parserchar))
			}
			if parserchar == parserEofCode {
				goto ret1
			}
			parserchar = -1
			goto parsernewstate /* try again in the same state */
		}
	}

	/* reduction by production parsern */
	if parserDebug >= 2 {
		__yyfmt__.Printf("reduce %v in:\n\t%v\n", parsern, parserStatname(parserstate))
	}

	parsernt := parsern
	parserpt := parserp
	_ = parserpt // guard against "declared and not used"

	parserp -= parserR2[parsern]
	parserVAL = parserS[parserp+1]

	/* consult goto table to find next state */
	parsern = parserR1[parsern]
	parserg := parserPgo[parsern]
	parserj := parserg + parserS[parserp].yys + 1

	if parserj >= parserLast {
		parserstate = parserAct[parserg]
	} else {
		parserstate = parserAct[parserj]
		if parserChk[parserstate] != -parsern {
			parserstate = parserAct[parserg]
		}
	}
	// dummy call; replaced with literal code
	switch parsernt {

	case 1:
		//line parser.y:65
		{
			parserlex.(*parserLex).out = parserS[parserpt-0].query
		}
	case 2:
		parserVAL.query = parserS[parserpt-0].query
	case 3:
		//line parser.y:72
		{
			parserVAL.query = intersectQuery{parserS[parserpt-2].query, parserS[parserpt-0].query}
		}
	case 4:
		//line parser.y:76
		{
			parserVAL.query = unionQuery{parserS[parserpt-2].query, parserS[parserpt-0].query}
		}
	case 5:
		//line parser.y:82
		{
			parserVAL.query = ipQuery{parserS[parserpt-0].ip, parserS[parserpt-0].ip}
		}
	case 6:
		//line parser.y:86
		{
			if parserS[parserpt-0].num < 0 || parserS[parserpt-0].num >= 65536 {
				parserlex.Error(fmt.Sprintf("invalid port %v", parserS[parserpt-0].num))
			}
			parserVAL.query = portQuery(parserS[parserpt-0].num)
		}
	case 7:
		//line parser.y:93
		{
			if parserS[parserpt-0].num < 0 || parserS[parserpt-0].num >= 65536 {
				parserlex.Error(fmt.Sprintf("invalid vlan %v", parserS[parserpt-0].num))
			}
			parserVAL.query = vlanQuery(parserS[parserpt-0].num)
		}
	case 8:
		//line parser.y:100
		{
			if parserS[parserpt-0].num < 0 || parserS[parserpt-0].num >= (1<<20) {
				parserlex.Error(fmt.Sprintf("invalid mpls %v", parserS[parserpt-0].num))
			}
			parserVAL.query = mplsQuery(parserS[parserpt-0].num)
		}
	case 9:
		//line parser.y:107
		{
			if parserS[parserpt-0].num < 0 || parserS[parserpt-0].num >= 256 {
				parserlex.Error(fmt.Sprintf("invalid proto %v", parserS[parserpt-0].num))
			}
			parserVAL.query = protocolQuery(parserS[parserpt-0].num)
		}
	case 10:
		//line parser.y:114
		{
			mask := net.CIDRMask(parserS[parserpt-0].num, len(parserS[parserpt-2].ip)*8)
			if mask == nil {
				parserlex.Error(fmt.Sprintf("bad cidr: %v/%v", parserS[parserpt-2].ip, parserS[parserpt-0].num))
			}
			from, to, err := ipsFromNet(parserS[parserpt-2].ip, mask)
			if err != nil {
				parserlex.Error(err.Error())
			}
			parserVAL.query = ipQuery{from, to}
		}
	case 11:
		//line parser.y:126
		{
			from, to, err := ipsFromNet(parserS[parserpt-2].ip, net.IPMask(parserS[parserpt-0].ip))
			if err != nil {
				parserlex.Error(err.Error())
			}
			parserVAL.query = ipQuery{from, to}
		}
	case 12:
		//line parser.y:134
		{
			parserVAL.query = parserS[parserpt-1].query
		}
	case 13:
		//line parser.y:138
		{
			parserVAL.query = protocolQuery(6)
		}
	case 14:
		//line parser.y:142
		{
			parserVAL.query = protocolQuery(17)
		}
	case 15:
		//line parser.y:146
		{
			parserVAL.query = protocolQuery(1)
		}
	case 16:
		//line parser.y:150
		{
			var t timeQuery
			t[1] = parserS[parserpt-0].time
			parserVAL.query = t
		}
	case 17:
		//line parser.y:156
		{
			var t timeQuery
			t[0] = parserS[parserpt-0].time
			parserVAL.query = t
		}
	case 18:
		//line parser.y:164
		{
			parserVAL.time = parserS[parserpt-0].time
		}
	case 19:
		//line parser.y:168
		{
			parserVAL.time = parserlex.(*parserLex).now.Add(-parserS[parserpt-1].dur)
		}
	}
	goto parserstack /* stack new state and value */
}
