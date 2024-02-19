package appsec

import "testing"

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
