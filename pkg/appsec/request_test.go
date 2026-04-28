package appsec

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestBodyDumper(t *testing.T) {
	tests := []struct {
		name   string
		req    *ParsedRequest
		expect *ParsedRequest
		filter func(r *ReqDumpFilter) *ReqDumpFilter
	}{
		{
			name: "default filter (cookie+authorization stripped + no body)",
			req: &ParsedRequest{
				Body:    []byte("yo some body"),
				Headers: map[string][]string{"cookie": {"toto"}, "authorization": {"tata"}, "foo": {"bar", "baz"}},
			},
			expect: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{"foo": {"bar", "baz"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r
			},
		},
		{
			name: "explicit empty filter",
			req: &ParsedRequest{
				Body:    []byte("yo some body"),
				Headers: map[string][]string{"cookie": {"toto"}, "authorization": {"tata"}, "foo": {"bar", "baz"}},
			},
			expect: &ParsedRequest{
				Body:    []byte("yo some body"),
				Headers: map[string][]string{"cookie": {"toto"}, "authorization": {"tata"}, "foo": {"bar", "baz"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.NoFilters()
			},
		},
		{
			name: "filter header",
			req: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{"test1": {"toto"}, "test2": {"tata"}},
			},
			expect: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{"test1": {"toto"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithNoBody().WithHeadersNameFilter("test2")
			},
		},
		{
			name: "filter header content",
			req: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{"test1": {"toto"}, "test2": {"tata"}},
			},
			expect: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{"test1": {"toto"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithHeadersContentFilter("tata")
			},
		},
		{
			name: "with headers",
			req: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{"cookie1": {"lol"}},
			},
			expect: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{"cookie1": {"lol"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithHeaders()
			},
		},
		{
			name: "drop headers",
			req: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{"toto": {"lol"}},
			},
			expect: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithNoHeaders()
			},
		},
		{
			name: "with body",
			req: &ParsedRequest{
				Body:    []byte("toto"),
				Headers: map[string][]string{"toto": {"lol"}},
			},
			expect: &ParsedRequest{
				Body:    []byte("toto"),
				Headers: map[string][]string{"toto": {"lol"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithBody()
			},
		},
		{
			name: "with empty args filter",
			req: &ParsedRequest{
				Args: map[string][]string{"toto": {"lol"}},
			},
			expect: &ParsedRequest{
				Args: map[string][]string{"toto": {"lol"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithEmptyArgsFilters()
			},
		},
		{
			name: "with args name filter",
			req: &ParsedRequest{
				Args: map[string][]string{"toto": {"lol"}, "totolol": {"lol"}},
			},
			expect: &ParsedRequest{
				Args: map[string][]string{"totolol": {"lol"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithArgsNameFilter("toto")
			},
		},
		{
			name: "WithEmptyHeadersFilters",
			req: &ParsedRequest{
				Args: map[string][]string{"cookie": {"lol"}, "totolol": {"lol"}},
			},
			expect: &ParsedRequest{
				Args: map[string][]string{"cookie": {"lol"}, "totolol": {"lol"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithEmptyHeadersFilters()
			},
		},
		{
			name: "WithArgsContentFilters",
			req: &ParsedRequest{
				Args: map[string][]string{"test": {"lol"}, "test2": {"toto"}},
			},
			expect: &ParsedRequest{
				Args: map[string][]string{"test": {"lol"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithArgsContentFilter("toto")
			},
		},
	}

	for idx, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			orig_dr := test.req.DumpRequest()
			result := test.filter(orig_dr).GetFilteredRequest()

			if len(result.Body) != len(test.expect.Body) {
				t.Fatalf("test %d (%s) failed, got %d, expected %d", idx, test.name, len(test.req.Body), len(test.expect.Body))
			}
			if len(result.Headers) != len(test.expect.Headers) {
				t.Fatalf("test %d (%s) failed, got %d, expected %d", idx, test.name, len(test.req.Headers), len(test.expect.Headers))
			}
			for k, v := range result.Headers {
				if len(v) != len(test.expect.Headers[k]) {
					t.Fatalf("test %d (%s) failed, got %d, expected %d", idx, test.name, len(v), len(test.expect.Headers[k]))
				}
			}
		})
	}
}

func makeTestRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()

	var bodyReader io.ReadCloser
	if body != nil {
		bodyReader = io.NopCloser(bytes.NewReader(body))
	}

	r := &http.Request{
		RemoteAddr: "1.2.3.4:1234",
		Body:       bodyReader,
		Header: http.Header{
			IPHeaderName:   []string{"1.2.3.4"},
			URIHeaderName:  []string{"/test"},
			VerbHeaderName: []string{"POST"},
		},
	}

	return r
}

func TestNewParsedRequestFromRequestBodyLimit(t *testing.T) {
	logger := log.WithField("test", "body-limit")

	tests := []struct {
		name             string
		body             []byte
		settings         BodySettings
		expectBody       []byte // nil means expect empty/nil body
		expectTruncated  bool
		expectExceeded   bool
	}{
		{
			name:     "no body",
			body:     nil,
			settings: BodySettings{MaxSize: 10, Action: BodySizeActionDrop},
		},
		{
			name:       "within limit",
			body:       bytes.Repeat([]byte("x"), 5),
			settings:   BodySettings{MaxSize: 10, Action: BodySizeActionDrop},
			expectBody: bytes.Repeat([]byte("x"), 5),
		},
		{
			name:       "exactly at limit",
			body:       bytes.Repeat([]byte("x"), 10),
			settings:   BodySettings{MaxSize: 10, Action: BodySizeActionDrop},
			expectBody: bytes.Repeat([]byte("x"), 10),
		},
		{
			name:           "over limit – drop",
			body:           bytes.Repeat([]byte("x"), 15),
			settings:       BodySettings{MaxSize: 10, Action: BodySizeActionDrop},
			expectExceeded: true,
		},
		{
			name:            "over limit – partial",
			body:            bytes.Repeat([]byte("x"), 15),
			settings:        BodySettings{MaxSize: 10, Action: BodySizeActionPartial},
			expectBody:      bytes.Repeat([]byte("x"), 10),
			expectTruncated: true,
		},
		{
			name:     "over limit – allow",
			body:     bytes.Repeat([]byte("x"), 15),
			settings: BodySettings{MaxSize: 10, Action: BodySizeActionAllow},
		},
		{
			name:       "zero MaxSize uses default (small body fits)",
			body:       bytes.Repeat([]byte("x"), 5),
			settings:   BodySettings{},
			expectBody: bytes.Repeat([]byte("x"), 5),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := makeTestRequest(t, test.body)

			parsed, err := NewParsedRequestFromRequest(r, logger, test.settings)
			require.NoError(t, err)

			require.Equal(t, test.expectTruncated, parsed.BodyTruncated)
			require.Equal(t, test.expectExceeded, parsed.BodySizeExceeded)
			require.Equal(t, test.expectBody, parsed.Body)
		})
	}
}
