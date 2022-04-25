# grokky

[![GoDoc](https://godoc.org/github.com/logrusorgru/grokky?status.svg)](https://godoc.org/github.com/logrusorgru/grokky)
[![WTFPL License](https://img.shields.io/badge/license-wtfpl-blue.svg)](http://www.wtfpl.net/about/)
[![Build Status](https://travis-ci.org/logrusorgru/grokky.svg)](https://travis-ci.org/logrusorgru/grokky)
[![Coverage Status](https://coveralls.io/repos/logrusorgru/grokky/badge.svg?branch=master)](https://coveralls.io/r/logrusorgru/grokky?branch=master)
[![GoReportCard](https://goreportcard.com/badge/logrusorgru/grokky)](https://goreportcard.com/report/logrusorgru/grokky)
[![Gitter](https://img.shields.io/badge/chat-on_gitter-46bc99.svg?logo=data:image%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIGhlaWdodD0iMTQiIHdpZHRoPSIxNCI%2BPGcgZmlsbD0iI2ZmZiI%2BPHJlY3QgeD0iMCIgeT0iMyIgd2lkdGg9IjEiIGhlaWdodD0iNSIvPjxyZWN0IHg9IjIiIHk9IjQiIHdpZHRoPSIxIiBoZWlnaHQ9IjciLz48cmVjdCB4PSI0IiB5PSI0IiB3aWR0aD0iMSIgaGVpZ2h0PSI3Ii8%2BPHJlY3QgeD0iNiIgeT0iNCIgd2lkdGg9IjEiIGhlaWdodD0iNCIvPjwvZz48L3N2Zz4%3D&logoWidth=10)](https://gitter.im/logrusorgru/grokky?utm_source=share-link&utm_medium=link&utm_campaign=share-link)

Package grokky is a pure Golang Grok-like patterns library, which can
help you to parse log files and other. This is based on
[RE2](https://en.wikipedia.org/wiki/RE2_%28software%29)
regexp that
[much more faster](https://swtch.com/~rsc/regexp/regexp1.html)
than
[Oniguruma](https://en.wikipedia.org/wiki/Oniguruma) in some cases.
Check out the "much more faster" article to understand the difference.

The library was disigned for creating many patterns and using it many
times. The behavior and capabilities are slightly different from the
original library. The goals of the library are:
1. simplicity,
2. fast,
3. ease of use.

# Also

See also another golang implementation
[vjeantet/grok](https://github.com/vjeantet/grok) that
is closer to the
[original](https://www.elastic.co/guide/en/logstash/current/plugins-filters-grok.html)
library.

The difference:

1. The grokky allows named captures only. Any name of a pattern is
  just name of a pattern and nothing more. You can treat is as an
  alias for regexp. It's impossible to use a name of a pattern as a
  capture group.  In some cases the grooky is similar to the grok that
  created as `g, err :=
  grok.NewWithConfig(&grok.Config{NamedCapturesOnly: true})`.

2. The grokky prefered top named group. If you have two patterns. And
  the second pattern has same named group and nested into first. Then
  the named group of the first pattern will be used. The grok uses last
  (closer to tail) group in any cases. But the grok also has
  `ParseToMultiMap` method. To see the difference explanation get the
  package (using `go get -t`) and run the following command
  `go test -v -run the_difference github.com/logrusorgru/grokky`. Or check
  out [source code of the test](https://github.com/logrusorgru/grokky/blob/master/bench_test.go#L134).

3. The grokky was designed as a factory of patterns. E.g. compile once and use
  many times.

# Get it

```
go get -u -t github.com/logrusorgru/grokky
```

Run test case

```
go test github.com/logrusorgru/grokky
```

Run benchmark comparsion with vjeantet/grok

```
go test -bench=.* github.com/logrusorgru/grokky
```


# Example


```go

package main

import (
	"github.com/logrusorgru/grokky"
	"fmt"
	"log"
	"time"
)

func createHost() grokky.Host {
	h := grokky.New()
	// add patterns to the Host
	h.Must("YEAR", `(?:\d\d){1,2}`)
	h.Must("MONTHNUM2", `0[1-9]|1[0-2]`)
	h.Must("MONTHDAY", `(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9]`)
	h.Must("HOUR", `2[0123]|[01]?[0-9]`)
	h.Must("MINUTE", `[0-5][0-9]`)
	h.Must("SECOND", `(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?`)
	h.Must("TIMEZONE", `Z%{HOUR}:%{MINUTE}`)
	h.Must("DATE", "%{YEAR:year}-%{MONTHNUM2:month}-%{MONTHDAY:day}")
	h.Must("TIME", "%{HOUR:hour}:%{MINUTE:min}:%{SECOND:sec}")
	return h
}

func main() {
	h := createHost()
	// compile the pattern for RFC3339 time
	p, err := h.Compile("%{DATE:date}T%{TIME:time}%{TIMEZONE:tz}")
	if err != nil {
		log.Fatal(err)
	}
	for k, v := range p.Parse(time.Now().Format(time.RFC3339)) {
		fmt.Printf("%s: %v\n", k, v)
	}
	//
	// Yes, it's better to use time.Parse for time values
	// but this is just example.
	//
}

```

# Performance note

Don't complicate regular expressions. Use simplest regular expressions possible.
Here is example about Nginx access log, combined format:

```go
h := New()

h.Must("NSS", `[^\s]*`) // not a space *
h.Must("NS", `[^\s]+`)  // not a space +
h.Must("NLB", `[^\]]+`) // not a left bracket +
h.Must("NQS", `[^"]*`)  // not a double quote *
h.Must("NQ", `[^"]+`)   // not a double quote +

h.Must("nginx", `%{NS:remote_addr}\s\-\s`+
	`%{NSS:remote_user}\s*\-\s\[`+
	`%{NLB:time_local}\]\s\"`+
	`%{NQ:request}\"\s`+
	`%{NS:status}\s`+
	`%{NS:body_bytes_sent}\s\"`+
	`%{NQ:http_referer}\"\s\"`+
	`%{NQ:user_agent}\"`)

nginx, err := h.Get("nginx")
if err != nil {
	panic(err)
}

for logLine := range catLogFileLineByLineChannel {
	values := nginx.Parse(logLine)

	// stuff

}
```

or there is a version (thanks for __@nanjj__)

```go
h := New()

h.Must("NSS", `[^\s]*`) // not a space *
h.Must("NS", `[^\s]+`)  // not a space +
h.Must("NLB", `[^\]]+`) // not a left bracket +
h.Must("NQS", `[^"]*`)  // not a double quote *
h.Must("NQ", `[^"]+`)   // not a double quote +
h.Must("A", `.*`)       // all (get tail)

h.Must("nginx", `%{NS:clientip}\s%{NSS:ident}\s%{NSS:auth}`+
	`\s\[`+
	`%{NLB:timestamp}\]\s\"`+
	`%{NS:verb}\s`+
	`%{NSS:request}\s`+
	`HTTP/%{NS:httpversion}\"\s`+
	`%{NS:response}\s`+
	`%{NS:bytes}\s\"`+
	`%{NQ:referrer}\"\s\"`+
	`%{NQ:agent}\"`+
	`%{A:blob}`)

// [...]
```

## More performance

Since the
[`grokky.Pattern`](https://godoc.org/github.com/logrusorgru/grokky#Pattern)
inherits [`regexp.Regexp`](https://godoc.org/regexp#Regexp), it's possible
to use methods of the `regexp.Regexp`. E.g. you can to use
[`FindStringSubmatch`](https://godoc.org/regexp#Regexp.FindStringSubmatch)
for example instead of `(grokky.Pattern).Parse`. Or any other method of
the `regexp.Regexp`.

Check out
[Benchmark_parse_vs_findStringSubmatch](https://github.com/logrusorgru/grokky/blob/master/bench_test.go#L409)
for example.

For my machine result of this becnhmark is (the map is `Parse`, and the slice is
`FindStringSubmatch`)

```
map-4      200000    9980 ns/op    1370 B/op    5 allocs/op
slice-4    200000    7508 ns/op     416 B/op    2 allocs/op
```

# Licensing

Copyright © 2016-2018 Konstantin Ivanov <kostyarin.ivanov@gmail.com>  
This work is free. It comes without any warranty, to the extent
permitted by applicable law. You can redistribute it and/or modify
it under the terms of the Do What The Fuck You Want To Public License,
Version 2, as published by Sam Hocevar. See the LICENSE file for
more details.
