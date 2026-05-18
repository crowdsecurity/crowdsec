package httpserver_test

// End-to-end benchmark comparing the lenient appsec httpserver against
// net/http's server on the same handler, same wire format, same payload.
//
// Run:
//
//	go test -bench=. -benchmem -count=3 \
//	    ./pkg/acquisition/modules/appsec/httpserver/
//
// Add -cpuprofile=cpu.out / -memprofile=mem.out to capture profiles, then
// inspect with `go tool pprof`.

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/appsec/httpserver"
)

// benchHandler mimics the cheap path of appsecHandler: drain the body and
// write a small JSON-shaped response. It deliberately does nothing else so
// the benchmark measures transport cost, not Coraza.
func benchHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"action":"allow"}`))
}

type serverStarter func(net.Listener, http.Handler) (stop func())

func startLenient(l net.Listener, h http.Handler) func() {
	s := &httpserver.Server{Handler: h}
	go func() { _ = s.Serve(l) }()
	return func() { _ = s.Close() }
}

func startStd(l net.Listener, h http.Handler) func() {
	s := &http.Server{Handler: h}
	go func() { _ = s.Serve(l) }()
	return func() { _ = s.Close() }
}

// buildRequest produces a representative bouncer→crowdsec request: the headers
// the bouncer always sets plus a body of the requested size.
func buildRequest(bodySize int) string {
	body := strings.Repeat("a", bodySize)
	var b strings.Builder
	b.WriteString("POST / HTTP/1.1\r\n")
	b.WriteString("Host: x\r\n")
	b.WriteString("X-Crowdsec-Appsec-Ip: 1.2.3.4\r\n")
	b.WriteString("X-Crowdsec-Appsec-Uri: /foo\r\n")
	b.WriteString("X-Crowdsec-Appsec-Verb: POST\r\n")
	b.WriteString("X-Crowdsec-Appsec-Api-Key: bench\r\n")
	b.WriteString("Content-Length: ")
	b.WriteString(strconv.Itoa(len(body)))
	b.WriteString("\r\n\r\n")
	b.WriteString(body)
	return b.String()
}

func runBench(b *testing.B, start serverStarter, bodySize int) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	stop := start(l, http.HandlerFunc(benchHandler))
	defer stop()

	req := buildRequest(bodySize)
	addr := l.Addr().String()

	b.ReportAllocs()
	b.SetBytes(int64(len(req)))
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()
		br := bufio.NewReader(c)
		for pb.Next() {
			if _, err := io.WriteString(c, req); err != nil {
				b.Fatal(err)
			}
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				b.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	})
}

func BenchmarkServer_Lenient_SmallBody(b *testing.B) { runBench(b, startLenient, 100) }
func BenchmarkServer_Std_SmallBody(b *testing.B)     { runBench(b, startStd, 100) }
func BenchmarkServer_Lenient_LargeBody(b *testing.B) { runBench(b, startLenient, 8*1024) }
func BenchmarkServer_Std_LargeBody(b *testing.B)     { runBench(b, startStd, 8*1024) }
