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

package query

import (
  "strconv"
  "net"
  "strings"
  "unicode"
  "errors"
)

%}

%union {
	num int
  ip net.IP
  str string
  query Query
}

%type	<query>	expr expr2

%token <str> HOST PORT PROTOCOL AND OR
%token <ip> IP
%token <num> NUM

%%

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
  $$ = portQuery($2)
}
|   PROTOCOL NUM
{
  $$ = protocolQuery($2)
}
|   '(' expr ')'
{
  $$ = $2
}

%%

// The parser uses the type <prefix>Lex as a lexer.  It must provide
// the methods Lex(*<prefix>SymType) int and Error(string).
type parserLex struct {
  in string
  pos int
  err error
}

var tokens = map[string]int{
 "host": HOST,
 "port": PORT,
 "protocol": PROTOCOL,
 "and": AND,
 "or": OR,
}

// The parser calls this method to get each new token.  This
// implementation returns operators and NUM.
func (x *parserLex) Lex(yylval *parserSymType) int {
  for x.pos < len(x.in) && unicode.IsSpace(rune(x.in[x.pos])) {
    x.pos++
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
  for t, i := range tokens {
    if strings.HasPrefix(x.in[x.pos:], t) {
      x.pos += len(t)
      return i
    }
  }
  switch c := x.in[x.pos]; c {
  case ':', '.', '(', ')':
    return int(c)
  }
  return -1
}

// The parser calls this method on a parse error.
func (x *parserLex) Error(s string) {
	x.err = errors.New(s)
}

func parse(in string) (Query, error) {
  lex := &parserLex{in: in}
	return parserParse(lex), lex.err
}
