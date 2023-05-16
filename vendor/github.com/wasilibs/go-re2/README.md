# go-re2

go-re2 is a drop-in replacement for the standard library [regexp][1] package which uses the C++
[re2][2] library for improved performance with large inputs or complex expressions. By default,
re2 is packaged as a WebAssembly module and accessed with the pure Go runtime, [wazero][3].
This means that it is compatible with any Go application, regardless of availability of cgo.

The library can also be used in a TinyGo application being compiled to WebAssembly. Currently,
`regexp` when compiled with TinyGo always has very slow performance and sometimes fails to
compile expressions completely.

Note that if your regular expressions or input are small, this library is slower than the
standard library. You will generally "know" if your application requires high performance for
complex regular expressions, for example in security filtering software. If you do not know
your app has such needs and are not using TinyGo, you should turn away now.

## Behavior differences

The library is almost fully compatible with the standard library regexp package, with just a few
behavior differences. These are likely corner cases that don't affect typical applications. It is
best to confirm them before proceeding.

- Invalid utf-8 strings are treated differently. The standard library silently replaces invalid utf-8
with the unicode replacement character. This library will stop consuming strings when encountering
invalid utf-8.
  - `experimental.CompileLatin1` can be used to match against non-utf8 strings

- `reflect.DeepEqual` cannot compare `Regexp` objects.

Continue to use the standard library if your usage would match any of these.

Searching this codebase for `// GAP` will allow finding tests that have been tweaked to demonstrate
behavior differences.

## API differences

All APIs found in `regexp` are available except

- `*Reader`: re2 does not support streaming input
- `*Func`: re2 does not support replacement with callback functions

Note that unlike many packages that wrap C++ libraries, there is no added `Close` type of method.
See the [rationale](./RATIONALE.md) for more details.

### Experimental APIs

The [experimental](./experimental) package contains APIs not part of standard `regexp` that are
incubating. They may in the future be moved to stable packages. The experimental package does not
provide any guarantee of API stability even across minor version updates.

## Usage

go-re2 is a standard Go library package and can be added to a go.mod file. It will work fine in
Go or TinyGo projects.

```
go get github.com/wasilibs/go-re2
```

Because the library is a drop-in replacement for the standard library, an import alias can make
migrating code to use it simple.

```go
import "regexp"
```

can be changed to

```go
import regexp "github.com/wasilibs/go-re2"
```

### cgo

This library also supports opting into using cgo to wrap re2 instead of using WebAssembly. This
requires having re2 installed and available via `pkg-config` on the system. The build tag `re2_cgo`
can be used to enable cgo support.

## Performance

Benchmarks are run against every commit in the [bench][4] workflow. GitHub action runners are highly
virtualized and do not have stable performance across runs, but the relative numbers within a run
should still be somewhat, though not precisely, informative.

### wafbench

wafbench tests the performance of replacing the regex operator of the OWASP [CoreRuleSet][5] and
[Coraza][6] implementation with this library. This benchmark is considered a real world performance
test, with the regular expressions being real ones used in production. Security filtering rules
often have highly complex expressions.

One run looks like this

```
name \ time/op     build/wafbench_stdlib.txt  build/wafbench.txt  build/wafbench_cgo.txt
WAF/FTW-2                         40.5s ± 1%          38.4s ± 2%              36.8s ± 1%
WAF/POST/1-2                     4.57ms ± 7%         5.21ms ± 5%             4.78ms ± 5%
WAF/POST/1000-2                  26.6ms ± 5%          8.1ms ± 2%              7.0ms ± 1%
WAF/POST/10000-2                  239ms ± 2%           31ms ± 4%               23ms ± 5%
WAF/POST/100000-2                 2.38s ± 2%          0.24s ± 4%              0.17s ± 2%
```

`FTW` is the time to run the standard CoreRuleSet test framework. The performance of this
library with WebAssembly, wafbench.txt, shows a slight improvement over the standard library
in this baseline test case.

The FTW test suite will issue many requests with various payloads, generally somewhat small.
The `POST` tests show the same ruleset applied to requests with payload sizes as shown, in bytes.
We see that only with the absolute smallest payload of 1 byte does the standard library perform
a bit better than this library. For any larger size, even a fairly typical 1KB, go-re2
greatly outperforms.

cgo seems to offer about a 30% improvement on WebAssembly in this library. Many apps may accept
the somewhat slower performance in exchange for the build and deployment flexibility of
WebAssembly but either option will work with no changes to the codebase.

### Microbenchmarks

Microbenchmarks are the same as included in the Go standard library. Full results can be
viewed in the workflow, a sample of results for one run looks like this

```
name \ time/op                  build/bench_stdlib.txt  build/bench.txt   build/bench_cgo.txt
Find-2                                      211ns ± 6%        965ns ± 4%            424ns ± 1%
Compile/Onepass-2                          5.21µs ± 0%     445.49µs ± 2%          21.30µs ± 4%
Compile/Medium-2                           11.6µs ± 0%      511.8µs ± 1%           33.1µs ± 3%
Compile/Hard-2                             95.1µs ± 0%     1425.0µs ± 1%          252.4µs ± 5%
Match/Easy0/16-2                           4.37ns ± 0%     457.30ns ± 1%         221.10ns ± 3%
Match/Easy0/32-2                           51.8ns ± 0%      451.8ns ± 2%          219.4ns ± 0%
Match/Easy0/1K-2                            275ns ± 0%        471ns ± 1%            218ns ± 0%
Match/Easy0/32K-2                          4.70µs ± 1%       1.29µs ± 2%           0.22µs ± 3%
Match/Easy0/1M-2                            270µs ± 0%        212µs ± 2%              0µs ± 3%
Match/Easy0/32M-2                          9.10ms ± 1%      10.03ms ± 1%           0.00ms ± 2%
Match/Easy0i/16-2                          4.37ns ± 0%     427.44ns ± 1%         226.04ns ± 5%
Match/Easy0i/32-2                           815ns ± 0%        429ns ± 2%            226ns ± 3%
Match/Easy0i/1K-2                          23.7µs ± 0%        0.4µs ± 1%            0.2µs ± 4%
Match/Easy0i/32K-2                         1.08ms ± 0%       0.00ms ± 1%           0.00ms ± 1%
Match/Easy0i/1M-2                          35.0ms ± 1%        0.2ms ± 4%            0.0ms ± 1%
Match/Easy0i/32M-2                          1.12s ± 1%        0.01s ± 9%            0.00s ± 1%
Match/Easy1/16-2                           4.36ns ± 0%     428.92ns ± 2%         222.84ns ± 3%
Match/Easy1/32-2                           48.3ns ± 0%      422.7ns ± 1%          219.8ns ± 4%
Match/Easy1/1K-2                            671ns ± 1%        438ns ± 1%            223ns ± 3%
Match/Easy1/32K-2                          32.2µs ± 1%        1.3µs ± 1%            0.2µs ± 0%
Match/Easy1/1M-2                           1.13ms ± 1%       0.20ms ± 1%           0.00ms ± 3%
Match/Easy1/32M-2                          36.0ms ± 1%        9.6ms ± 1%            0.0ms ± 1%
Match/Medium/16-2                          4.37ns ± 1%     427.46ns ± 1%         217.50ns ± 0%
Match/Medium/32-2                           894ns ± 0%        425ns ± 2%            217ns ± 0%
Match/Medium/1K-2                          25.4µs ± 0%        0.4µs ± 1%            0.2µs ± 3%
Match/Medium/32K-2                         1.12ms ± 2%       0.00ms ± 1%           0.00ms ± 0%
Match/Medium/1M-2                          35.7ms ± 1%        0.2ms ± 1%            0.0ms ± 3%
Match/Medium/32M-2                          1.15s ± 0%        0.01s ± 4%            0.00s ± 3%
Match/Hard/16-2                            4.37ns ± 0%     427.10ns ± 1%         224.10ns ± 3%
Match/Hard/32-2                            1.19µs ± 0%       0.42µs ± 1%           0.22µs ± 3%
Match/Hard/1K-2                            36.1µs ± 0%        0.4µs ± 1%            0.2µs ± 3%
Match/Hard/32K-2                           1.71ms ± 6%       0.00ms ± 1%           0.00ms ± 3%
Match/Hard/1M-2                            54.7ms ± 6%        0.2ms ± 3%            0.0ms ± 2%
Match/Hard/32M-2                            1.76s ± 6%        0.01s ± 3%            0.00s ± 4%
Match/Hard1/16-2                           3.61µs ± 2%       0.51µs ± 1%           0.24µs ± 1%
Match/Hard1/32-2                           7.04µs ± 1%       0.61µs ± 0%           0.27µs ± 0%
Match/Hard1/1K-2                            214µs ± 1%          7µs ± 0%              2µs ± 0%
Match/Hard1/32K-2                          8.30ms ± 4%       0.20ms ± 0%           0.07ms ± 0%
Match/Hard1/1M-2                            268ms ± 6%          7ms ± 1%              2ms ± 0%
Match/Hard1/32M-2                           8.37s ± 4%        0.21s ± 1%            0.07s ± 0%
MatchParallel/Easy0/16-2                   2.37ns ± 0%     472.38ns ± 1%         160.54ns ± 1%
MatchParallel/Easy0/32-2                   27.3ns ± 0%      475.6ns ± 2%          161.9ns ± 2%
MatchParallel/Easy0/1K-2                    139ns ± 1%        492ns ± 0%            162ns ± 3%
MatchParallel/Easy0/32K-2                  2.41µs ± 1%       1.45µs ± 1%           0.16µs ± 2%
MatchParallel/Easy0/1M-2                    139µs ± 1%        224µs ± 1%              0µs ± 4%
MatchParallel/Easy0/32M-2                  4.67ms ± 2%      10.12ms ± 5%           0.00ms ± 3%
MatchParallel/Easy0i/16-2                  2.37ns ± 0%     473.04ns ± 1%         183.26ns ± 2%
MatchParallel/Easy0i/32-2                   417ns ± 1%        471ns ± 1%            185ns ± 1%
MatchParallel/Easy0i/1K-2                  12.1µs ± 1%        0.5µs ± 2%            0.2µs ± 2%
MatchParallel/Easy0i/32K-2                  553µs ± 1%          1µs ± 1%              0µs ± 1%
MatchParallel/Easy0i/1M-2                  17.7ms ± 0%        0.2ms ± 3%            0.0ms ± 3%
MatchParallel/Easy0i/32M-2                  1.12s ± 0%        0.01s ± 5%            0.00s ± 2%
MatchParallel/Easy1/16-2                   2.37ns ± 0%     466.56ns ± 4%         150.72ns ± 4%
MatchParallel/Easy1/32-2                   23.4ns ± 0%      468.1ns ± 1%          148.6ns ± 2%
MatchParallel/Easy1/1K-2                    338ns ± 0%        488ns ± 1%            149ns ± 3%
MatchParallel/Easy1/32K-2                  16.5µs ± 1%        1.4µs ± 1%            0.1µs ± 3%
MatchParallel/Easy1/1M-2                    573µs ± 1%        226µs ± 5%              0µs ± 1%
MatchParallel/Easy1/32M-2                  18.2ms ± 2%       10.0ms ± 3%            0.0ms ± 1%
MatchParallel/Medium/16-2                  2.38ns ± 1%     469.96ns ± 3%         158.48ns ± 3%
MatchParallel/Medium/32-2                   460ns ± 2%        474ns ± 2%            156ns ± 2%
MatchParallel/Medium/1K-2                  13.0µs ± 1%        0.5µs ± 1%            0.2µs ± 3%
MatchParallel/Medium/32K-2                  564µs ± 0%          1µs ± 2%              0µs ± 4%
MatchParallel/Medium/1M-2                  18.5ms ± 2%        0.2ms ± 3%            0.0ms ± 4%
MatchParallel/Medium/32M-2                  1.15s ± 1%        0.01s ± 6%            0.00s ± 4%
MatchParallel/Hard/16-2                    2.37ns ± 0%     468.86ns ± 1%         147.88ns ± 3%
MatchParallel/Hard/32-2                     607ns ± 1%        465ns ± 1%            149ns ± 4%
MatchParallel/Hard/1K-2                    18.5µs ± 1%        0.5µs ± 1%            0.1µs ± 3%
MatchParallel/Hard/32K-2                    849µs ± 5%          1µs ± 1%              0µs ± 3%
MatchParallel/Hard/1M-2                    26.8ms ± 1%        0.2ms ± 1%            0.0ms ± 2%
MatchParallel/Hard/32M-2                    1.68s ± 2%        0.01s ± 2%            0.00s ± 2%
MatchParallel/Hard1/16-2                   1.83µs ± 1%       0.57µs ± 1%           0.17µs ± 3%
MatchParallel/Hard1/32-2                   3.62µs ± 1%       0.66µs ± 2%           0.19µs ± 0%
MatchParallel/Hard1/1K-2                    109µs ± 0%          7µs ± 0%              1µs ± 1%
MatchParallel/Hard1/32K-2                  4.18ms ± 5%       0.21ms ± 1%           0.04ms ± 3%
MatchParallel/Hard1/1M-2                    134ms ± 1%          7ms ± 1%              1ms ± 0%
MatchParallel/Hard1/32M-2                   8.48s ± 0%        0.21s ± 0%            0.03s ± 1%

name \ alloc/op                 build/bench_stdlib.txt  build/bench.txt   build/bench_cgo.txt
Find-2                                      0.00B            72.00B ± 0%           16.00B ± 0%
Compile/Onepass-2                          4.06kB ± 0%     598.70kB ± 0%           0.16kB ± 0%
Compile/Medium-2                           9.42kB ± 0%     598.77kB ± 0%           0.24kB ± 0%
Compile/Hard-2                             84.8kB ± 0%      912.3kB ± 0%            2.4kB ± 0%
```

Most benchmarks are similar to `Find`, testing simple expressions with small input. In all of these,
the standard library performs much better. To reiterate the guidance at the top of this README, if
you only use simple expressions with small input, you should not use this library.

The compilation benchmarks show that re2 is much slower to compile expressions than the standard
library - this is more than just the overhead of foreign function invocation. This likely results
in the improved performance at runtime in other cases. They also show 500KB+ memory usage per
compilation - the resting memory usage per expression seems to be around ~300KB, much higher than
the standard library. There is significantly more memory usage when using WebAssembly - if this
is not acceptable, setting up the build toolchain for cgo may be worth it. Note the allocation
numbers for cgo are inaccurate as cgo will allocate memory outside of Go - however it should be
inline with the standard library (this needs to be explored in the future).

The match benchmarks show the performance tradeoffs for complexity vs input size. We see the standard
library perform the best with low complexity and size, but for high complexity or high input size,
go-re2 with WebAssembly outperforms, often significantly. Notable is `Hard1`, where even on the smallest
size this library outperforms. The expression is `ABCD|CDEF|EFGH|GHIJ|IJKL|KLMN|MNOP|OPQR|QRST|STUV|UVWX|WXYZ`,
a simple OR of literals - re2 has the concept of regex sets and likely is able to optimize this in a
special way. The CoreRuleSet contains many expressions of a form like this - this possibly indicates good
performance in real world use cases.

Note that because WebAssembly currently only supports single-threaded operation, any compiled expression
can not be executed concurrently and uses locks for safety. When executing many expressions in sequence, it can
be common to not have much contention, but it may be necessary to use a `sync.Pool` of compiled expressions
for concurrency in certain cases, at the expense of more memory usage. When looking at `MatchParallel`, we see
almost perfect scaling in the stdlib case indicating fully parallel execution, no scaling with wazero, and some
scaling with cgo - thread safety is managed by re2 itself in cgo mode which also uses mutexes internally.

[1]: https://pkg.go.dev/regexp
[2]: https://github.com/google/re2
[3]: https://wazero.io
[4]: https://github.com/wasilibs/go-re2/actions/workflows/bench.yaml
[5]: https://github.com/coreruleset/coreruleset
[6]: https://github.com/corazawaf/coraza
