package exprhelpers

import (
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/expr-lang/expr"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/csnet"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/enrichment"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func getDBClient(t *testing.T) *database.Client {
	t.Helper()

	ctx := t.Context()

	testDBClient, err := database.NewClient(ctx, &csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbName: "crowdsec",
		DbPath: ":memory:",
	}, nil)
	require.NoError(t, err)

	return testDBClient
}

func TestVisitor(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		name   string
		filter string
		result bool
		env    map[string]any
		err    error
	}{
		{
			name:   "debug : no variable",
			filter: "'crowdsec' startsWith 'crowdse'",
			result: true,
			err:    nil,
			env:    map[string]any{},
		},
		{
			name:   "debug : simple variable",
			filter: "'crowdsec' startsWith static_one && 1 == 1",
			result: true,
			err:    nil,
			env:    map[string]any{"static_one": string("crowdse")},
		},
		{
			name:   "debug : simple variable re-used",
			filter: "static_one.foo == 'bar' && static_one.foo != 'toto'",
			result: true,
			err:    nil,
			env:    map[string]any{"static_one": map[string]string{"foo": "bar"}},
		},
		{
			name:   "debug : can't compile",
			filter: "static_one.foo.toto == 'lol'",
			result: false,
			err:    errors.New("bad syntax"),
			env:    map[string]any{"static_one": map[string]string{"foo": "bar"}},
		},
		{
			name:   "debug : can't compile #2",
			filter: "static_one.f!oo.to/to == 'lol'",
			result: false,
			err:    errors.New("bad syntax"),
			env:    map[string]any{"static_one": map[string]string{"foo": "bar"}},
		},
		{
			name:   "debug : can't compile #3",
			filter: "",
			result: false,
			err:    errors.New("bad syntax"),
			env:    map[string]any{"static_one": map[string]string{"foo": "bar"}},
		},
	}

	log.SetLevel(log.DebugLevel)

	for _, test := range tests {
		compiledFilter, err := expr.Compile(test.filter, GetExprOptions(test.env)...)
		if err != nil && test.err == nil {
			t.Fatalf("compile: %s", err)
		}

		if compiledFilter != nil {
			result, err := expr.Run(compiledFilter, test.env)
			if err != nil && test.err == nil {
				t.Fatalf("run: %s", err)
			}

			if isOk := assert.Equal(t, test.result, result); !isOk {
				t.Fatalf("test '%s' : NOK", test.filter)
			}
		}
	}
}

func TestMatch(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		glob string
		val  string
		ret  bool
		expr string
	}{
		{"foo", "foo", true, `Match(pattern, name)`},
		{"foo", "bar", false, `Match(pattern, name)`},
		{"foo*", "foo", true, `Match(pattern, name)`},
		{"foo*", "foobar", true, `Match(pattern, name)`},
		{"foo*", "barfoo", false, `Match(pattern, name)`},
		{"foo*", "bar", false, `Match(pattern, name)`},
		{"*foo", "foo", true, `Match(pattern, name)`},
		{"*foo", "barfoo", true, `Match(pattern, name)`},
		{"foo*r", "foobar", true, `Match(pattern, name)`},
		{"foo*r", "foobazr", true, `Match(pattern, name)`},
		{"foo?ar", "foobar", true, `Match(pattern, name)`},
		{"foo?ar", "foobazr", false, `Match(pattern, name)`},
		{"foo?ar", "foobaz", false, `Match(pattern, name)`},
		{"*foo?ar?", "foobar", false, `Match(pattern, name)`},
		{"*foo?ar?", "foobare", true, `Match(pattern, name)`},
		{"*foo?ar?", "rafoobar", false, `Match(pattern, name)`},
		{"*foo?ar?", "rafoobare", true, `Match(pattern, name)`},
	}
	for _, test := range tests {
		env := map[string]any{
			"pattern": test.glob,
			"name":    test.val,
		}

		vm, err := expr.Compile(test.expr, GetExprOptions(env)...)
		if err != nil {
			t.Fatalf("pattern:%s val:%s NOK %s", test.glob, test.val, err)
		}

		ret, err := expr.Run(vm, env)
		require.NoError(t, err)

		if isOk := assert.Equal(t, test.ret, ret); !isOk {
			t.Fatalf("pattern:%s val:%s NOK %t !=  %t", test.glob, test.val, ret, test.ret)
		}
	}
}

// just to verify that the function is available, real tests are in TestExtractQueryParam
func TestExtractQueryParamExpr(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		name   string
		env    map[string]any
		code   string
		result []string
		err    string
	}{
		{
			name: "ExtractQueryParam() test: basic test",
			env: map[string]any{
				"query": "/foo?a=1&b=2",
			},
			code:   "ExtractQueryParam(query, 'a')",
			result: []string{"1"},
		},
	}
	for _, test := range tests {
		program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
		require.NoError(t, err)
		output, err := expr.Run(program, test.env)
		require.NoError(t, err)
		require.Equal(t, test.result, output)
		log.Printf("test '%s' : OK", test.name)
	}
}

// just to verify that the function is available, real tests are in TestParseQuery
func TestParseQueryInExpr(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		name   string
		env    map[string]any
		code   string
		result url.Values
		err    string
	}{
		{
			name: "ParseQuery() test: basic test",
			env: map[string]any{
				"query":      "a=1&b=2",
				"ParseQuery": ParseQuery,
			},
			code:   "ParseQuery(query)",
			result: url.Values{"a": {"1"}, "b": {"2"}},
		},
	}
	for _, test := range tests {
		program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
		require.NoError(t, err)
		output, err := expr.Run(program, test.env)
		require.NoError(t, err)
		require.Equal(t, test.result, output)
		log.Printf("test '%s' : OK", test.name)
	}
}

func TestDistanceHelper(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		lat1  string
		lon1  string
		lat2  string
		lon2  string
		dist  float64
		valid bool
		expr  string
		name  string
	}{
		{"51.45", "1.15", "41.54", "12.27", 1389.1793118293067, true, `Distance(lat1, lon1, lat2, lon2)`, "valid"},
		{"lol", "1.15", "41.54", "12.27", 0.0, false, `Distance(lat1, lon1, lat2, lon2)`, "invalid lat1"},
		{"0.0", "0.0", "12.1", "12.1", 0.0, true, `Distance(lat1, lon1, lat2, lon2)`, "empty coord"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := map[string]any{
				"lat1": test.lat1,
				"lon1": test.lon1,
				"lat2": test.lat2,
				"lon2": test.lon2,
			}

			vm, err := expr.Compile(test.expr, GetExprOptions(env)...)
			if err != nil {
				t.Fatalf("pattern:%s val:%s NOK %s", test.lat1, test.lon1, err)
			}

			ret, err := expr.Run(vm, env)
			if test.valid {
				require.NoError(t, err)
				assert.InDelta(t, test.dist, ret, 0.000001)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestRegexpCacheBehavior(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	filename := "test_data_re.txt"
	err = FileInit("testdata", filename, "regex")
	require.NoError(t, err)

	// cache with no TTL
	err = RegexpCacheInit(filename, enrichment.DataProvider{Type: "regex", Size: ptr.Of(1)})
	require.NoError(t, err)

	ret, _ := RegexpInFile("crowdsec", filename)
	assert.False(t, ret.(bool))
	assert.Equal(t, 1, dataFileRegexCache[filename].Len(false))

	ret, _ = RegexpInFile("Crowdsec", filename)
	assert.True(t, ret.(bool))
	assert.Equal(t, 1, dataFileRegexCache[filename].Len(false))

	// cache with TTL
	ttl := 500 * time.Millisecond
	err = RegexpCacheInit(filename, enrichment.DataProvider{Type: "regex", Size: ptr.Of(2), TTL: &ttl})
	require.NoError(t, err)

	ret, _ = RegexpInFile("crowdsec", filename)
	assert.False(t, ret.(bool))
	assert.Equal(t, 1, dataFileRegexCache[filename].Len(true))

	time.Sleep(1 * time.Second)
	assert.Equal(t, 0, dataFileRegexCache[filename].Len(true))
}

func TestRegexpInFile(t *testing.T) {
	if err := Init(nil); err != nil {
		t.Fatal(err)
	}

	err := FileInit("testdata", "test_data_re.txt", "regex")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		filter string
		result bool
		err    error
	}{
		{
			name:   "RegexpInFile() test: lower case word in data file",
			filter: "RegexpInFile('crowdsec', 'test_data_re.txt')",
			result: false,
			err:    nil,
		},
		{
			name:   "RegexpInFile() test: Match exactly",
			filter: "RegexpInFile('Crowdsec', 'test_data_re.txt')",
			result: true,
			err:    nil,
		},
		{
			name:   "RegexpInFile() test: match with word before",
			filter: "RegexpInFile('test Crowdsec', 'test_data_re.txt')",
			result: true,
			err:    nil,
		},
		{
			name:   "RegexpInFile() test: match with word before and other case",
			filter: "RegexpInFile('test CrowdSec', 'test_data_re.txt')",
			result: true,
			err:    nil,
		},
	}

	for _, test := range tests {
		compiledFilter, err := expr.Compile(test.filter, GetExprOptions(map[string]any{})...)
		if err != nil {
			t.Fatal(err)
		}

		result, err := expr.Run(compiledFilter, map[string]any{})
		if err != nil {
			t.Fatal(err)
		}

		if isOk := assert.Equal(t, test.result, result); !isOk {
			t.Fatalf("test '%s': NOK", test.name)
		}
	}
}

func TestFileInit(t *testing.T) {
	if err := Init(nil); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		filename string
		types    string
		result   int
		err      error
	}{
		{
			name:     "file with type:string",
			filename: "test_data.txt",
			types:    "string",
			result:   3,
		},
		{
			name:     "file with type:string and empty lines + commentaries",
			filename: "test_empty_line.txt",
			types:    "string",
			result:   3,
		},
		{
			name:     "file with type:re",
			filename: "test_data_re.txt",
			types:    "regex",
			result:   2,
		},
		{
			name:     "file without type",
			filename: "test_data_no_type.txt",
			types:    "",
		},
	}

	for _, test := range tests {
		err := FileInit("testdata", test.filename, test.types)
		if err != nil {
			t.Fatal(err)
		}

		switch test.types {
		case "string":
			if _, ok := dataFile[test.filename]; !ok {
				t.Fatalf("test '%s' : NOK", test.name)
			}

			if isOk := assert.Len(t, dataFile[test.filename], test.result); !isOk {
				t.Fatalf("test '%s' : NOK", test.name)
			}
		case "regex":
			if _, ok := dataFileRegex[test.filename]; !ok {
				t.Fatalf("test '%s' : NOK", test.name)
			}

			if isOk := assert.Len(t, dataFileRegex[test.filename], test.result); !isOk {
				t.Fatalf("test '%s' : NOK", test.name)
			}
		default:
			if _, ok := dataFileRegex[test.filename]; ok {
				t.Fatalf("test '%s' : NOK", test.name)
			}

			if _, ok := dataFile[test.filename]; ok {
				t.Fatalf("test '%s' : NOK", test.name)
			}
		}

		log.Printf("test '%s' : OK", test.name)
	}
}

func TestFile(t *testing.T) {
	if err := Init(nil); err != nil {
		t.Fatal(err)
	}

	err := FileInit("testdata", "test_data.txt", "string")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		filter string
		result bool
		err    error
	}{
		{
			name:   "File() test: word in file",
			filter: "'Crowdsec' in File('test_data.txt')",
			result: true,
			err:    nil,
		},
		{
			name:   "File() test: word in file but different case",
			filter: "'CrowdSecurity' in File('test_data.txt')",
			result: false,
			err:    nil,
		},
		{
			name:   "File() test: word not in file",
			filter: "'test' in File('test_data.txt')",
			result: false,
			err:    nil,
		},
		{
			name:   "File() test: filepath provided doesn't exist",
			filter: "'test' in File('non_existing_data.txt')",
			result: false,
			err:    nil,
		},
	}

	for _, test := range tests {
		compiledFilter, err := expr.Compile(test.filter, GetExprOptions(map[string]any{})...)
		if err != nil {
			t.Fatal(err)
		}

		result, err := expr.Run(compiledFilter, map[string]any{})
		if err != nil {
			t.Fatal(err)
		}

		if isOk := assert.Equal(t, test.result, result); !isOk {
			t.Fatalf("test '%s' : NOK", test.name)
		}

		log.Printf("test '%s' : OK", test.name)
	}
}

func TestIpInRange(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)
	tests := []struct {
		name   string
		env    map[string]any
		code   string
		result bool
		err    string
	}{
		{
			name: "IpInRange() test: basic test",
			env: map[string]any{
				"ip":      "192.168.0.1",
				"ipRange": "192.168.0.0/24",
			},
			code:   "IpInRange(ip, ipRange)",
			result: true,
			err:    "",
		},
		{
			name: "IpInRange() test: malformed IP",
			env: map[string]any{
				"ip":      "192.168.0",
				"ipRange": "192.168.0.0/24",
			},
			code:   "IpInRange(ip, ipRange)",
			result: false,
			err:    "",
		},
		{
			name: "IpInRange() test: malformed IP range",
			env: map[string]any{
				"ip":      "192.168.0.0/255",
				"ipRange": "192.168.0.0/24",
			},
			code:   "IpInRange(ip, ipRange)",
			result: false,
			err:    "",
		},
	}

	for _, test := range tests {
		program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
		require.NoError(t, err)
		output, err := expr.Run(program, test.env)
		require.NoError(t, err)
		require.Equal(t, test.result, output)
		log.Printf("test '%s' : OK", test.name)
	}
}

func TestIpToRange(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		name           string
		env            map[string]any
		code           string
		want           string
		wantCompileErr string
		wantRunErr     string
		wantLog        string
	}{
		{
			name: "IpToRange() test: IPv4",
			env: map[string]any{
				"ip":      "192.168.1.1",
				"netmask": "16",
			},
			code: "IpToRange(ip, netmask)",
			want: "192.168.0.0/16",
		},
		{
			name: "IpToRange() test: IPv6",
			env: map[string]any{
				"ip":      "2001:db8::1",
				"netmask": "/64",
			},
			code: "IpToRange(ip, netmask)",
			want: "2001:db8::/64",
		},
		{
			name: "IpToRange() test: malformed netmask",
			env: map[string]any{
				"ip":      "192.168.0.1",
				"netmask": "test",
			},
			code: "IpToRange(ip, netmask)",
			want: "",
		},
		{
			name: "IpToRange() test: malformed IP",
			env: map[string]any{
				"ip":      "a.b.c.d",
				"netmask": "24",
			},
			code: "IpToRange(ip, netmask)",
		},
		{
			name: "IpToRange() test: too high netmask",
			env: map[string]any{
				"ip":      "192.168.1.1",
				"netmask": "35",
			},
			code:    "IpToRange(ip, netmask)",
			wantLog: "can't create prefix from IP address '192.168.1.1' and mask '35': prefix length 35 too large for IPv4",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := cstest.CaptureLogs(t)

			program, err := expr.Compile(tc.code, GetExprOptions(tc.env)...)
			cstest.RequireErrorContains(t, err, tc.wantCompileErr)

			if tc.wantCompileErr != "" {
				return
			}

			output, err := expr.Run(program, tc.env)
			cstest.RequireErrorContains(t, err, tc.wantRunErr)

			if tc.wantRunErr != "" {
				return
			}

			if tc.wantLog != "" {
				assert.Contains(t, buf.String(), tc.wantLog)
			}

			require.Equal(t, tc.want, output)
		})
	}
}

func TestAtof(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		name   string
		env    map[string]any
		code   string
		result float64
	}{
		{
			name: "Atof() test: basic test",
			env: map[string]any{
				"testFloat": "1.5",
			},
			code:   "Atof(testFloat)",
			result: 1.5,
		},
		{
			name: "Atof() test: bad float",
			env: map[string]any{
				"testFloat": "1aaa.5",
			},
			code:   "Atof(testFloat)",
			result: 0.0,
		},
	}

	for _, test := range tests {
		program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
		require.NoError(t, err)
		output, err := expr.Run(program, test.env)
		require.NoError(t, err)
		require.InDelta(t, test.result, output, 0.000001)
	}
}

func TestUpper(t *testing.T) {
	testStr := "test"
	wantStr := "TEST"

	env := map[string]any{
		"testStr": testStr,
	}

	err := Init(nil)
	require.NoError(t, err)
	vm, err := expr.Compile("Upper(testStr)", GetExprOptions(env)...)
	require.NoError(t, err)

	out, err := expr.Run(vm, env)

	require.NoError(t, err)

	v, ok := out.(string)
	if !ok {
		t.Fatal("Upper() should return a string")
	}

	if v != wantStr {
		t.Fatal("Upper() should return test in upper case")
	}
}

func TestTimeNow(t *testing.T) {
	now, _ := TimeNow()

	ti, err := time.Parse(time.RFC3339, now.(string))
	if err != nil {
		t.Fatalf("Error parsing the return value of TimeNow: %s", err)
	}

	if -1*time.Until(ti) > time.Second {
		t.Fatal("TimeNow func should return time.Now().UTC()")
	}

	log.Print("test 'TimeNow()' : OK")
}

func TestAverageInterval(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	// Use a fixed base time to eliminate execution time variance
	baseTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		env  map[string]any
		code string
		want time.Duration
	}{
		{
			name: "AverageInterval() test: two times with 1 second difference",
			env: map[string]any{
				"times": []time.Time{baseTime, baseTime.Add(time.Second)},
			},
			code: "AverageInterval(times)",
			want: time.Second,
		},
		{
			name: "AverageInterval() test: two times with 1 second difference (reverse order)",
			env: map[string]any{
				"times": []time.Time{baseTime.Add(time.Second), baseTime},
			},
			code: "AverageInterval(times)",
			want: time.Second,
		},
		{
			name: "AverageInterval() test: three times with varying intervals",
			env: map[string]any{
				"times": []time.Time{
					baseTime,
					baseTime.Add(2 * time.Second), // 2s gap
					baseTime.Add(6 * time.Second), // 4s gap
				},
			},
			code: "AverageInterval(times)",
			want: 3 * time.Second, // (2s + 4s) / 2 = 3s average
		},
		{
			name: "AverageInterval() test: four times with equal intervals",
			env: map[string]any{
				"times": []time.Time{
					baseTime,
					baseTime.Add(time.Hour),
					baseTime.Add(2 * time.Hour),
					baseTime.Add(3 * time.Hour),
				},
			},
			code: "AverageInterval(times)",
			want: time.Hour, // all intervals are 1 hour
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
			require.NoError(t, err)
			got, err := expr.Run(program, test.env)
			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}

func TestMedianInterval(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	// Use a fixed base time to eliminate execution time variance
	baseTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		env         map[string]any
		code        string
		want        time.Duration
		wantErr     bool
		errContains string
	}{
		{
			name: "MedianInterval() test: two times with 1 second difference",
			env: map[string]any{
				"times": []time.Time{baseTime, baseTime.Add(time.Second)},
			},
			code: "MedianInterval(times)",
			want: time.Second,
		},
		{
			name: "MedianInterval() test: three times - odd number of intervals",
			env: map[string]any{
				"times": []time.Time{
					baseTime,
					baseTime.Add(2 * time.Second),  // 2s gap
					baseTime.Add(5 * time.Second),  // 3s gap
					baseTime.Add(11 * time.Second), // 6s gap
				},
			},
			code: "MedianInterval(times)",
			want: 3 * time.Second, // median of [2s, 3s, 6s] = 3s
		},
		{
			name: "MedianInterval() test: four times - even number of intervals",
			env: map[string]any{
				"times": []time.Time{
					baseTime,
					baseTime.Add(1 * time.Second),  // 1s gap
					baseTime.Add(3 * time.Second),  // 2s gap
					baseTime.Add(7 * time.Second),  // 4s gap
					baseTime.Add(15 * time.Second), // 8s gap
				},
			},
			code: "MedianInterval(times)",
			want: 3 * time.Second, // median of [1s, 2s, 4s, 8s] = (2s + 4s) / 2 = 3s
		},
		{
			name: "MedianInterval() test: reverse order times",
			env: map[string]any{
				"times": []time.Time{
					baseTime.Add(11 * time.Second),
					baseTime.Add(5 * time.Second),
					baseTime.Add(2 * time.Second),
					baseTime,
				},
			},
			code: "MedianInterval(times)",
			want: 3 * time.Second, // should sort first, then calculate median
		},
		{
			name: "MedianInterval() test: equal intervals",
			env: map[string]any{
				"times": []time.Time{
					baseTime,
					baseTime.Add(time.Hour),
					baseTime.Add(2 * time.Hour),
					baseTime.Add(3 * time.Hour),
					baseTime.Add(4 * time.Hour),
				},
			},
			code: "MedianInterval(times)",
			want: time.Hour, // all intervals are 1 hour, median = 1 hour
		},
		{
			name: "MedianInterval() test: mixed small and large intervals",
			env: map[string]any{
				"times": []time.Time{
					baseTime,
					baseTime.Add(1 * time.Millisecond),    // 1ms gap
					baseTime.Add(1001 * time.Millisecond), // 1000ms = 1s gap
					baseTime.Add(2001 * time.Millisecond), // 1000ms = 1s gap
				},
			},
			code: "MedianInterval(times)",
			want: time.Second, // median of [1ms, 1s, 1s] = 1s
		},
		{
			name: "MedianInterval() test: only one time (error case)",
			env: map[string]any{
				"times": []time.Time{baseTime},
			},
			code:        "MedianInterval(times)",
			wantErr:     true,
			errContains: "need at least two times",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
			require.NoError(t, err)

			got, err := expr.Run(program, test.env)

			if test.wantErr {
				require.Error(t, err)
				if test.errContains != "" {
					assert.Contains(t, err.Error(), test.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}

func TestAverageMedianWithQueues(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	// Use fixed base time for stability
	baseTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)

	type mockQueue struct {
		Time    time.Time
		StrTime string
	}

	tests := []struct {
		name        string
		env         map[string]any
		code        string
		want        time.Duration
		wantErr     bool
		errContains string
	}{
		{
			name: "AverageInterval() test mockQueue: two times with 1 second difference",
			env: map[string]any{
				"queue": []mockQueue{
					{Time: baseTime},
					{Time: baseTime.Add(time.Second)},
				},
			},
			code: "AverageInterval(map(queue,{ #.Time }))",
			want: time.Second,
		},
		{
			name: "MedianInterval() test mockQueue: three times with varying intervals",
			env: map[string]any{
				"queue": []mockQueue{
					{Time: baseTime},
					{Time: baseTime.Add(2 * time.Second)},  // 2s gap
					{Time: baseTime.Add(5 * time.Second)},  // 3s gap
					{Time: baseTime.Add(11 * time.Second)}, // 6s gap
				},
			},
			code: "MedianInterval(map(queue,{ #.Time }))",
			want: 3 * time.Second, // median of [2s, 3s, 6s] = 3s
		},
		{
			name: "AverageInterval() test slicing: last 3 items from 5-item queue",
			env: map[string]any{
				"queue": []mockQueue{
					{Time: baseTime},                       // ignored
					{Time: baseTime.Add(1 * time.Second)},  // ignored
					{Time: baseTime.Add(10 * time.Second)}, // start: index -3
					{Time: baseTime.Add(12 * time.Second)}, // +2s gap
					{Time: baseTime.Add(16 * time.Second)}, // +4s gap
				},
			},
			code: "AverageInterval(map(queue[-3:],{ #.Time }))",
			want: 3 * time.Second, // (2s + 4s) / 2 = 3s average
		},
		{
			name: "MedianInterval() test slicing: last 3 items from 5-item queue",
			env: map[string]any{
				"queue": []mockQueue{
					{Time: baseTime},                       // ignored
					{Time: baseTime.Add(1 * time.Second)},  // ignored
					{Time: baseTime.Add(10 * time.Second)}, // start: index -3
					{Time: baseTime.Add(12 * time.Second)}, // +2s gap
					{Time: baseTime.Add(16 * time.Second)}, // +4s gap
				},
			},
			code: "MedianInterval(map(queue[-3:],{ #.Time }))",
			want: 3 * time.Second, // median of [2s, 4s] = (2s + 4s) / 2 = 3s
		},
		{
			name: "AverageInterval() test slicing: first 3 items from 5-item queue",
			env: map[string]any{
				"queue": []mockQueue{
					{Time: baseTime},                       // start
					{Time: baseTime.Add(3 * time.Second)},  // +3s gap
					{Time: baseTime.Add(8 * time.Second)},  // +5s gap
					{Time: baseTime.Add(20 * time.Second)}, // ignored
					{Time: baseTime.Add(30 * time.Second)}, // ignored
				},
			},
			code: "AverageInterval(map(queue[:3],{ #.Time }))",
			want: 4 * time.Second, // (3s + 5s) / 2 = 4s average
		},
		{
			name: "MedianInterval() test slicing: middle 3 items from 5-item queue",
			env: map[string]any{
				"queue": []mockQueue{
					{Time: baseTime},                       // ignored
					{Time: baseTime.Add(5 * time.Second)},  // start: index 1
					{Time: baseTime.Add(7 * time.Second)},  // +2s gap
					{Time: baseTime.Add(12 * time.Second)}, // +5s gap
					{Time: baseTime.Add(25 * time.Second)}, // ignored
				},
			},
			code: "MedianInterval(map(queue[1:4],{ #.Time }))",
			want: 3*time.Second + 500*time.Millisecond, // median of [2s, 5s] = (2s + 5s) / 2 = 3.5s
		},
		{
			name: "AverageInterval() test slicing: last 2 items from 6-item queue",
			env: map[string]any{
				"queue": []mockQueue{
					{Time: baseTime},                       // ignored
					{Time: baseTime.Add(1 * time.Second)},  // ignored
					{Time: baseTime.Add(2 * time.Second)},  // ignored
					{Time: baseTime.Add(3 * time.Second)},  // ignored
					{Time: baseTime.Add(10 * time.Second)}, // start: index -2
					{Time: baseTime.Add(15 * time.Second)}, // +5s gap
				},
			},
			code: "AverageInterval(map(queue[-2:],{ #.Time }))",
			want: 5 * time.Second, // only one interval: 5s
		},
		{
			name: "MedianInterval() test slicing: single item slice (error case)",
			env: map[string]any{
				"queue": []mockQueue{
					{Time: baseTime},
					{Time: baseTime.Add(5 * time.Second)},
					{Time: baseTime.Add(10 * time.Second)},
				},
			},
			code:        "MedianInterval(map(queue[1:2],{ #.Time }))",
			wantErr:     true,
			errContains: "need at least two times",
		},
		{
			name: "AverageInterval() test error: slice of strings instead of times",
			env: map[string]any{
				"stringQueue": []string{"hello", "world", "test"},
			},
			code:        "AverageInterval(stringQueue)",
			wantErr:     true,
			errContains: "cannot use []string as argument",
		},
		{
			name: "MedianInterval() test error: mixed types in slice",
			env: map[string]any{
				"mixedQueue": []mockQueue{
					{Time: baseTime},
				},
				"stringValue": "not a time",
			},
			code:        "MedianInterval([mixedQueue[0].Time, stringValue])",
			wantErr:     true,
			errContains: "element at index 1 is not a time.Time",
		},
		{
			name: "AverageInterval() test error: mapping string time field instead of Time field",
			env: map[string]any{
				"queue": []mockQueue{
					{Time: baseTime, StrTime: "2023-01-01T12:00:00Z"},
					{Time: baseTime.Add(time.Second), StrTime: "2023-01-01T12:00:01Z"},
					{Time: baseTime.Add(3 * time.Second), StrTime: "2023-01-01T12:00:03Z"},
				},
			},
			code:        "AverageInterval(map(queue, { #.StrTime }))",
			wantErr:     true,
			errContains: "element at index 0 is not a time.Time",
		},
		{
			name: "MedianInterval() test error: accidentally mapping wrong field type",
			env: map[string]any{
				"queueWithStrings": []mockQueue{
					{Time: baseTime, StrTime: "not-a-time-format"},
					{Time: baseTime.Add(2 * time.Second), StrTime: "also-not-time"},
					{Time: baseTime.Add(5 * time.Second), StrTime: "still-not-time"},
				},
			},
			code:        "MedianInterval(map(queueWithStrings, { #.StrTime }))",
			wantErr:     true,
			errContains: "element at index 0 is not a time.Time",
		},
		{
			name: "AverageInterval() test success: converting string timestamps with date() function",
			env: map[string]any{
				"queueWithValidStrings": []mockQueue{
					{Time: baseTime, StrTime: "2023-01-01T12:00:00Z"},
					{Time: baseTime.Add(time.Second), StrTime: "2023-01-01T12:00:01Z"},
					{Time: baseTime.Add(3 * time.Second), StrTime: "2023-01-01T12:00:03Z"},
				},
			},
			code: "AverageInterval(map(queueWithValidStrings, { date(#.StrTime) }))",
			want: time.Second + 500*time.Millisecond, // (1s + 2s) / 2 = 1.5s
		},
		{
			name: "MedianInterval() test success: converting RFC3339 string timestamps",
			env: map[string]any{
				"queueWithRFC3339": []mockQueue{
					{Time: baseTime, StrTime: "2023-01-01T12:00:00Z"},
					{Time: baseTime.Add(2 * time.Second), StrTime: "2023-01-01T12:00:02Z"},
					{Time: baseTime.Add(5 * time.Second), StrTime: "2023-01-01T12:00:05Z"},
					{Time: baseTime.Add(11 * time.Second), StrTime: "2023-01-01T12:00:11Z"},
				},
			},
			code: "MedianInterval(map(queueWithRFC3339, { date(#.StrTime) }))",
			want: 3 * time.Second, // median of [2s, 3s, 6s] = 3s
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			program, err := expr.Compile(test.code, GetExprOptions(test.env)...)

			if test.wantErr {
				if err != nil {
					// Compile-time error (type checking)
					if test.errContains != "" {
						assert.Contains(t, err.Error(), test.errContains)
					}
					return
				}
				// Runtime error
				_, err := expr.Run(program, test.env)
				require.Error(t, err)
				if test.errContains != "" {
					assert.Contains(t, err.Error(), test.errContains)
				}
				return
			}

			require.NoError(t, err)
			got, err := expr.Run(program, test.env)
			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}

func TestParseUri(t *testing.T) {
	tests := []struct {
		name   string
		env    map[string]any
		code   string
		result map[string][]string
		err    string
	}{
		{
			name: "ParseUri() test: basic test",
			env: map[string]any{
				"uri":      "/foo?a=1&b=2",
				"ParseUri": ParseUri,
			},
			code:   "ParseUri(uri)",
			result: map[string][]string{"a": {"1"}, "b": {"2"}},
			err:    "",
		},
		{
			name: "ParseUri() test: no param",
			env: map[string]any{
				"uri":      "/foo",
				"ParseUri": ParseUri,
			},
			code:   "ParseUri(uri)",
			result: map[string][]string{},
			err:    "",
		},
		{
			name: "ParseUri() test: extra question mark",
			env: map[string]any{
				"uri":      "/foo?a=1&b=2?",
				"ParseUri": ParseUri,
			},
			code:   "ParseUri(uri)",
			result: map[string][]string{"a": {"1"}, "b": {"2?"}},
			err:    "",
		},
		{
			name: "ParseUri() test: weird params",
			env: map[string]any{
				"uri":      "/foo?&?&&&&?=123",
				"ParseUri": ParseUri,
			},
			code:   "ParseUri(uri)",
			result: map[string][]string{"?": {"", "123"}},
			err:    "",
		},
		{
			name: "ParseUri() test: bad encoding",
			env: map[string]any{
				"uri":      "/foo?a=%%F",
				"ParseUri": ParseUri,
			},
			code:   "ParseUri(uri)",
			result: map[string][]string{},
			err:    "",
		},
	}

	for _, test := range tests {
		program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
		require.NoError(t, err)
		output, err := expr.Run(program, test.env)
		require.NoError(t, err)
		require.Equal(t, test.result, output)
		log.Printf("test '%s' : OK", test.name)
	}
}

func TestQueryEscape(t *testing.T) {
	tests := []struct {
		name   string
		env    map[string]any
		code   string
		result string
		err    string
	}{
		{
			name: "QueryEscape() test: basic test",
			env: map[string]any{
				"uri":         "/foo?a=1&b=2",
				"QueryEscape": QueryEscape,
			},
			code:   "QueryEscape(uri)",
			result: "%2Ffoo%3Fa%3D1%26b%3D2",
			err:    "",
		},
		{
			name: "QueryEscape() test: basic test",
			env: map[string]any{
				"uri":         "/foo?a=1&&b=<>'\"",
				"QueryEscape": QueryEscape,
			},
			code:   "QueryEscape(uri)",
			result: "%2Ffoo%3Fa%3D1%26%26b%3D%3C%3E%27%22",
			err:    "",
		},
	}

	for _, test := range tests {
		program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
		require.NoError(t, err)
		output, err := expr.Run(program, test.env)
		require.NoError(t, err)
		require.Equal(t, test.result, output)
		log.Printf("test '%s' : OK", test.name)
	}
}

func TestPathEscape(t *testing.T) {
	tests := []struct {
		name   string
		env    map[string]any
		code   string
		result string
		err    string
	}{
		{
			name: "PathEscape() test: basic test",
			env: map[string]any{
				"uri":        "/foo?a=1&b=2",
				"PathEscape": PathEscape,
			},
			code:   "PathEscape(uri)",
			result: "%2Ffoo%3Fa=1&b=2",
			err:    "",
		},
		{
			name: "PathEscape() test: basic test with more special chars",
			env: map[string]any{
				"uri":        "/foo?a=1&&b=<>'\"",
				"PathEscape": PathEscape,
			},
			code:   "PathEscape(uri)",
			result: "%2Ffoo%3Fa=1&&b=%3C%3E%27%22",
			err:    "",
		},
	}

	for _, test := range tests {
		program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
		require.NoError(t, err)
		output, err := expr.Run(program, test.env)
		require.NoError(t, err)
		require.Equal(t, test.result, output)
		log.Printf("test '%s' : OK", test.name)
	}
}

func TestPathUnescape(t *testing.T) {
	tests := []struct {
		name   string
		env    map[string]any
		code   string
		result string
		err    string
	}{
		{
			name: "PathUnescape() test: basic test",
			env: map[string]any{
				"uri":          "%2Ffoo%3Fa=1&b=%3C%3E%27%22",
				"PathUnescape": PathUnescape,
			},
			code:   "PathUnescape(uri)",
			result: "/foo?a=1&b=<>'\"",
			err:    "",
		},
		{
			name: "PathUnescape() test: basic test with more special chars",
			env: map[string]any{
				"uri":          "/$%7Bjndi",
				"PathUnescape": PathUnescape,
			},
			code:   "PathUnescape(uri)",
			result: "/${jndi",
			err:    "",
		},
	}

	for _, test := range tests {
		program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
		require.NoError(t, err)
		output, err := expr.Run(program, test.env)
		require.NoError(t, err)
		require.Equal(t, test.result, output)
		log.Printf("test '%s' : OK", test.name)
	}
}

func TestQueryUnescape(t *testing.T) {
	tests := []struct {
		name   string
		env    map[string]any
		code   string
		result string
		err    string
	}{
		{
			name: "QueryUnescape() test: basic test",
			env: map[string]any{
				"uri":           "%2Ffoo%3Fa=1&b=%3C%3E%27%22",
				"QueryUnescape": QueryUnescape,
			},
			code:   "QueryUnescape(uri)",
			result: "/foo?a=1&b=<>'\"",
			err:    "",
		},
		{
			name: "QueryUnescape() test: basic test with more special chars",
			env: map[string]any{
				"uri":           "/$%7Bjndi",
				"QueryUnescape": QueryUnescape,
			},
			code:   "QueryUnescape(uri)",
			result: "/${jndi",
			err:    "",
		},
	}

	for _, test := range tests {
		program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
		require.NoError(t, err)
		output, err := expr.Run(program, test.env)
		require.NoError(t, err)
		require.Equal(t, test.result, output)
		log.Printf("test '%s' : OK", test.name)
	}
}

func TestLower(t *testing.T) {
	tests := []struct {
		name   string
		env    map[string]any
		code   string
		result string
		err    string
	}{
		{
			name: "Lower() test: basic test",
			env: map[string]any{
				"name":  "ABCDEFG",
				"Lower": Lower,
			},
			code:   "Lower(name)",
			result: "abcdefg",
			err:    "",
		},
		{
			name: "Lower() test: basic test with more special chars",
			env: map[string]any{
				"name":  "AbcDefG!#",
				"Lower": Lower,
			},
			code:   "Lower(name)",
			result: "abcdefg!#",
			err:    "",
		},
	}

	for _, test := range tests {
		program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
		require.NoError(t, err)
		output, err := expr.Run(program, test.env)
		require.NoError(t, err)
		require.Equal(t, test.result, output)
		log.Printf("test '%s' : OK", test.name)
	}
}

func TestGetDecisionsCount(t *testing.T) {
	ctx := t.Context()

	existingIP := "1.2.3.4"
	unknownIP := "1.2.3.5"

	rng, err := csnet.NewRange(existingIP)
	if err != nil {
		t.Errorf("unable to convert '%s' to int: %s", existingIP, err)
	}

	// Add sample data to DB
	dbClient = getDBClient(t)

	decision := dbClient.Ent.Decision.Create().
		SetUntil(time.Now().Add(time.Hour)).
		SetScenario("crowdsec/test").
		SetStartIP(rng.Start.Addr).
		SetStartSuffix(rng.Start.Sfx).
		SetEndIP(rng.End.Addr).
		SetEndSuffix(rng.End.Sfx).
		SetIPSize(int64(rng.Size())).
		SetType("ban").
		SetScope("IP").
		SetValue(existingIP).
		SetOrigin("CAPI").
		SaveX(ctx)

	if decision == nil {
		require.Error(t, errors.New("Failed to create sample decision"))
	}

	err = Init(dbClient)
	require.NoError(t, err)

	tests := []struct {
		name   string
		env    map[string]any
		code   string
		result string
		err    string
	}{
		{
			name: "GetDecisionsCount() test: existing IP count",
			env: map[string]any{
				"Alert": &models.Alert{
					Source: &models.Source{
						Value: &existingIP,
					},
					Decisions: []*models.Decision{
						{
							Value: &existingIP,
						},
					},
				},
			},
			code:   "Sprintf('%d', GetDecisionsCount(Alert.GetValue()))",
			result: "1",
			err:    "",
		},
		{
			name: "GetDecisionsCount() test: unknown IP count",
			env: map[string]any{
				"Alert": &models.Alert{
					Source: &models.Source{
						Value: &unknownIP,
					},
					Decisions: []*models.Decision{
						{
							Value: &unknownIP,
						},
					},
				},
			},
			code:   "Sprintf('%d', GetDecisionsCount(Alert.GetValue()))",
			result: "0",
			err:    "",
		},
	}

	for _, test := range tests {
		program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
		require.NoError(t, err)
		output, err := expr.Run(program, test.env)
		require.NoError(t, err)
		require.Equal(t, test.result, output)
		log.Printf("test '%s' : OK", test.name)
	}
}

func TestGetDecisionsSinceCount(t *testing.T) {
	ctx := t.Context()

	existingIP := "1.2.3.4"
	unknownIP := "1.2.3.5"

	rng, err := csnet.NewRange(existingIP)
	if err != nil {
		t.Errorf("unable to convert '%s' to int: %s", existingIP, err)
	}
	// Add sample data to DB
	dbClient = getDBClient(t)

	decision := dbClient.Ent.Decision.Create().
		SetUntil(time.Now().Add(time.Hour)).
		SetScenario("crowdsec/test").
		SetStartIP(rng.Start.Addr).
		SetStartSuffix(rng.Start.Sfx).
		SetEndIP(rng.End.Addr).
		SetEndSuffix(rng.End.Sfx).
		SetIPSize(int64(rng.Size())).
		SetType("ban").
		SetScope("IP").
		SetValue(existingIP).
		SetOrigin("CAPI").
		SaveX(ctx)
	if decision == nil {
		require.Error(t, errors.New("Failed to create sample decision"))
	}

	decision2 := dbClient.Ent.Decision.Create().
		SetCreatedAt(time.Now().AddDate(0, 0, -1)).
		SetUntil(time.Now().AddDate(0, 0, -1)).
		SetScenario("crowdsec/test").
		SetStartIP(rng.Start.Addr).
		SetStartSuffix(rng.Start.Sfx).
		SetEndIP(rng.End.Addr).
		SetEndSuffix(rng.End.Sfx).
		SetIPSize(int64(rng.Size())).
		SetType("ban").
		SetScope("IP").
		SetValue(existingIP).
		SetOrigin("CAPI").
		SaveX(ctx)

	if decision2 == nil {
		require.Error(t, errors.New("Failed to create sample decision"))
	}

	err = Init(dbClient)
	require.NoError(t, err)

	tests := []struct {
		name   string
		env    map[string]any
		code   string
		result string
		err    string
	}{
		{
			name: "GetDecisionsSinceCount() test: existing IP count since more than 1 day",
			env: map[string]any{
				"Alert": &models.Alert{
					Source: &models.Source{
						Value: &existingIP,
					},
					Decisions: []*models.Decision{
						{
							Value: &existingIP,
						},
					},
				},
			},
			code:   "Sprintf('%d', GetDecisionsSinceCount(Alert.GetValue(), '25h'))",
			result: "2",
			err:    "",
		},
		{
			name: "GetDecisionsSinceCount() test: existing IP count since more than 1 hour",
			env: map[string]any{
				"Alert": &models.Alert{
					Source: &models.Source{
						Value: &existingIP,
					},
					Decisions: []*models.Decision{
						{
							Value: &existingIP,
						},
					},
				},
			},
			code:   "Sprintf('%d', GetDecisionsSinceCount(Alert.GetValue(), '1h'))",
			result: "1",
			err:    "",
		},
		{
			name: "GetDecisionsSinceCount() test: unknown IP count",
			env: map[string]any{
				"Alert": &models.Alert{
					Source: &models.Source{
						Value: &unknownIP,
					},
					Decisions: []*models.Decision{
						{
							Value: &unknownIP,
						},
					},
				},
			},
			code:   "Sprintf('%d', GetDecisionsSinceCount(Alert.GetValue(), '1h'))",
			result: "0",
			err:    "",
		},
	}

	for _, test := range tests {
		program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
		require.NoError(t, err)
		output, err := expr.Run(program, test.env)
		require.NoError(t, err)
		require.Equal(t, test.result, output)
		log.Printf("test '%s' : OK", test.name)
	}
}

func TestGetActiveDecisionsCount(t *testing.T) {
	ctx := t.Context()

	existingIP := "1.2.3.4"
	unknownIP := "1.2.3.5"

	rng, err := csnet.NewRange(existingIP)
	if err != nil {
		t.Errorf("unable to convert '%s' to int: %s", existingIP, err)
	}

	// Add sample data to DB
	dbClient = getDBClient(t)

	decision := dbClient.Ent.Decision.Create().
		SetUntil(time.Now().UTC().Add(time.Hour)).
		SetScenario("crowdsec/test").
		SetStartIP(rng.Start.Addr).
		SetStartSuffix(rng.Start.Sfx).
		SetEndIP(rng.End.Addr).
		SetEndSuffix(rng.End.Sfx).
		SetIPSize(int64(rng.Size())).
		SetType("ban").
		SetScope("IP").
		SetValue(existingIP).
		SetOrigin("CAPI").
		SaveX(ctx)

	if decision == nil {
		require.Error(t, errors.New("Failed to create sample decision"))
	}

	expiredDecision := dbClient.Ent.Decision.Create().
		SetUntil(time.Now().UTC().Add(-time.Hour)).
		SetScenario("crowdsec/test").
		SetStartIP(rng.Start.Addr).
		SetStartSuffix(rng.Start.Sfx).
		SetEndIP(rng.End.Addr).
		SetEndSuffix(rng.End.Sfx).
		SetIPSize(int64(rng.Size())).
		SetType("ban").
		SetScope("IP").
		SetValue(existingIP).
		SetOrigin("CAPI").
		SaveX(ctx)

	if expiredDecision == nil {
		require.Error(t, errors.New("Failed to create sample decision"))
	}

	err = Init(dbClient)
	require.NoError(t, err)

	tests := []struct {
		name   string
		env    map[string]any
		code   string
		result string
		err    string
	}{
		{
			name: "GetActiveDecisionsCount() test: existing IP count",
			env: map[string]any{
				"Alert": &models.Alert{
					Source: &models.Source{
						Value: &existingIP,
					},
					Decisions: []*models.Decision{
						{
							Value: &existingIP,
						},
					},
				},
			},
			code:   "Sprintf('%d', GetActiveDecisionsCount(Alert.GetValue()))",
			result: "1",
			err:    "",
		},
		{
			name: "GetActiveDecisionsCount() test: unknown IP count",
			env: map[string]any{
				"Alert": &models.Alert{
					Source: &models.Source{
						Value: &unknownIP,
					},
					Decisions: []*models.Decision{
						{
							Value: &unknownIP,
						},
					},
				},
			},
			code:   "Sprintf('%d', GetActiveDecisionsCount(Alert.GetValue()))",
			result: "0",
			err:    "",
		},
	}

	for _, test := range tests {
		program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
		require.NoError(t, err)
		output, err := expr.Run(program, test.env)
		require.NoError(t, err)
		require.Equal(t, test.result, output)
		log.Printf("test '%s' : OK", test.name)
	}
}

func TestGetActiveDecisionsTimeLeft(t *testing.T) {
	ctx := t.Context()

	existingIP := "1.2.3.4"
	unknownIP := "1.2.3.5"

	rng, err := csnet.NewRange(existingIP)
	if err != nil {
		t.Errorf("unable to convert '%s' to int: %s", existingIP, err)
	}

	// Add sample data to DB
	dbClient = getDBClient(t)

	decision := dbClient.Ent.Decision.Create().
		SetUntil(time.Now().UTC().Add(time.Hour)).
		SetScenario("crowdsec/test").
		SetStartIP(rng.Start.Addr).
		SetStartSuffix(rng.Start.Sfx).
		SetEndIP(rng.End.Addr).
		SetEndSuffix(rng.End.Sfx).
		SetIPSize(int64(rng.Size())).
		SetType("ban").
		SetScope("IP").
		SetValue(existingIP).
		SetOrigin("CAPI").
		SaveX(ctx)

	if decision == nil {
		require.Error(t, errors.New("Failed to create sample decision"))
	}

	longerDecision := dbClient.Ent.Decision.Create().
		SetUntil(time.Now().UTC().Add(2 * time.Hour)).
		SetScenario("crowdsec/test").
		SetStartIP(rng.Start.Addr).
		SetStartSuffix(rng.Start.Sfx).
		SetEndIP(rng.End.Addr).
		SetEndSuffix(rng.End.Sfx).
		SetIPSize(int64(rng.Size())).
		SetType("ban").
		SetScope("IP").
		SetValue(existingIP).
		SetOrigin("CAPI").
		SaveX(ctx)

	if longerDecision == nil {
		require.Error(t, errors.New("Failed to create sample decision"))
	}

	err = Init(dbClient)
	require.NoError(t, err)

	tests := []struct {
		name string
		env  map[string]any
		code string
		min  float64
		max  float64
		err  string
	}{
		{
			name: "GetActiveDecisionsTimeLeft() test: existing IP time left",
			env: map[string]any{
				"Alert": &models.Alert{
					Source: &models.Source{
						Value: &existingIP,
					},
					Decisions: []*models.Decision{
						{
							Value: &existingIP,
						},
					},
				},
			},
			code: "GetActiveDecisionsTimeLeft(Alert.GetValue())",
			min:  7195, // 5 seconds margin to make sure the test doesn't fail randomly in the CI
			max:  7200,
			err:  "",
		},
		{
			name: "GetActiveDecisionsTimeLeft() test: unknown IP time left",
			env: map[string]any{
				"Alert": &models.Alert{
					Source: &models.Source{
						Value: &unknownIP,
					},
					Decisions: []*models.Decision{
						{
							Value: &unknownIP,
						},
					},
				},
			},
			code: "GetActiveDecisionsTimeLeft(Alert.GetValue())",
			min:  0,
			max:  0,
			err:  "",
		},
		{
			name: "GetActiveDecisionsTimeLeft() test: existing IP and call time.Duration method",
			env: map[string]any{
				"Alert": &models.Alert{
					Source: &models.Source{
						Value: &existingIP,
					},
					Decisions: []*models.Decision{
						{
							Value: &existingIP,
						},
					},
				},
			},
			code: "GetActiveDecisionsTimeLeft(Alert.GetValue()).Hours()",
			min:  2,
			max:  2,
		},
		{
			name: "GetActiveDecisionsTimeLeft() test: unknown IP and call time.Duration method",
			env: map[string]any{
				"Alert": &models.Alert{
					Source: &models.Source{
						Value: &unknownIP,
					},
					Decisions: []*models.Decision{
						{
							Value: &unknownIP,
						},
					},
				},
			},
			code: "GetActiveDecisionsTimeLeft(Alert.GetValue()).Hours()",
			min:  0,
			max:  0,
		},
	}

	delta := 0.001

	for _, test := range tests {
		program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
		require.NoError(t, err)
		output, err := expr.Run(program, test.env)
		require.NoError(t, err)

		switch o := output.(type) {
		case time.Duration:
			require.LessOrEqual(t, int(o.Seconds()), int(test.max))
			require.GreaterOrEqual(t, int(o.Seconds()), int(test.min))
		case float64:
			require.LessOrEqual(t, o, test.max+delta)
			require.GreaterOrEqual(t, o, test.min-delta)
		default:
			t.Fatal("GetActiveDecisionsTimeLeft() should return a time.Duration or a float64")
		}
	}
}

func TestParseUnixTime(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    time.Time
		wantErr string
	}{
		{
			name:  "ParseUnix() test: valid value with milli",
			value: "1672239773.3590894",
			want:  time.Date(2022, 12, 28, 15, 2, 53, 0, time.UTC),
		},
		{
			name:  "ParseUnix() test: valid value without milli",
			value: "1672239773",
			want:  time.Date(2022, 12, 28, 15, 2, 53, 0, time.UTC),
		},
		{
			name:    "ParseUnix() test: invalid input",
			value:   "AbcDefG!#",
			want:    time.Time{},
			wantErr: "unable to parse AbcDefG!# as unix timestamp",
		},
		{
			name:    "ParseUnix() test: negative value",
			value:   "-1000",
			want:    time.Time{},
			wantErr: "unable to parse -1000 as unix timestamp",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output, err := ParseUnixTime(tc.value)
			cstest.RequireErrorContains(t, err, tc.wantErr)

			if tc.wantErr != "" {
				return
			}

			require.WithinDuration(t, tc.want, output.(time.Time), time.Second)
		})
	}
}

func TestIsIp(t *testing.T) {
	if err := Init(nil); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		expr         string
		value        string
		want         bool
		wantBuildErr bool
	}{
		{
			name:  "IsIPV4() test: valid IPv4",
			expr:  `IsIPV4(value)`,
			value: "1.2.3.4",
			want:  true,
		},
		{
			name:  "IsIPV6() test: valid IPv6",
			expr:  `IsIPV6(value)`,
			value: "1.2.3.4",
			want:  false,
		},
		{
			name:  "IsIPV6() test: valid IPv6",
			expr:  `IsIPV6(value)`,
			value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			want:  true,
		},
		{
			name:  "IsIPV4() test: valid IPv6",
			expr:  `IsIPV4(value)`,
			value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			want:  false,
		},
		{
			name:  "IsIP() test: invalid IP",
			expr:  `IsIP(value)`,
			value: "foo.bar",
			want:  false,
		},
		{
			name:  "IsIP() test: valid IPv4",
			expr:  `IsIP(value)`,
			value: "1.2.3.4",
			want:  true,
		},
		{
			name:  "IsIP() test: valid IPv6",
			expr:  `IsIP(value)`,
			value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			want:  true,
		},
		{
			name:  "IsIPV4() test: invalid IPv4",
			expr:  `IsIPV4(value)`,
			value: "foo.bar",
			want:  false,
		},
		{
			name:  "IsIPV6() test: invalid IPv6",
			expr:  `IsIPV6(value)`,
			value: "foo.bar",
			want:  false,
		},
		{
			name:         "IsIPV4() test: invalid type",
			expr:         `IsIPV4(42)`,
			value:        "",
			want:         false,
			wantBuildErr: true,
		},
		{
			name:         "IsIP() test: invalid type",
			expr:         `IsIP(42)`,
			value:        "",
			want:         false,
			wantBuildErr: true,
		},
		{
			name:         "IsIPV6() test: invalid type",
			expr:         `IsIPV6(42)`,
			value:        "",
			want:         false,
			wantBuildErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vm, err := expr.Compile(tc.expr, GetExprOptions(map[string]any{"value": tc.value})...)
			if tc.wantBuildErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			output, err := expr.Run(vm, map[string]any{"value": tc.value})
			require.NoError(t, err)
			assert.IsType(t, tc.want, output)
			assert.Equal(t, tc.want, output.(bool))
		})
	}
}

func TestToString(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		name  string
		value any
		want  string
		expr  string
	}{
		{
			name:  "ToString() test: valid string",
			value: "foo",
			want:  "foo",
			expr:  `ToString(value)`,
		},
		{
			name:  "ToString() test: valid string",
			value: any("foo"),
			want:  "foo",
			expr:  `ToString(value)`,
		},
		{
			name:  "ToString() test: invalid type",
			value: 1,
			want:  "",
			expr:  `ToString(value)`,
		},
		{
			name:  "ToString() test: invalid type 2",
			value: any(nil),
			want:  "",
			expr:  `ToString(value)`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vm, err := expr.Compile(tc.expr, GetExprOptions(map[string]any{"value": tc.value})...)
			require.NoError(t, err)
			output, err := expr.Run(vm, map[string]any{"value": tc.value})
			require.NoError(t, err)
			require.Equal(t, tc.want, output)
		})
	}
}

func TestB64Decode(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		name           string
		value          any
		want           string
		expr           string
		wantBuildErr   bool
		wantRuntimeErr bool
	}{
		{
			name:         "B64Decode() test: valid string",
			value:        "Zm9v",
			want:         "foo",
			expr:         `B64Decode(value)`,
			wantBuildErr: false,
		},
		{
			name:           "B64Decode() test: invalid string",
			value:          "foo",
			want:           "",
			expr:           `B64Decode(value)`,
			wantBuildErr:   false,
			wantRuntimeErr: true,
		},
		{
			name:         "B64Decode() test: invalid type",
			value:        1,
			want:         "",
			expr:         `B64Decode(value)`,
			wantBuildErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vm, err := expr.Compile(tc.expr, GetExprOptions(map[string]any{"value": tc.value})...)
			if tc.wantBuildErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			output, err := expr.Run(vm, map[string]any{"value": tc.value})
			if tc.wantRuntimeErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, output)
		})
	}
}

func TestParseKv(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		name           string
		value          string
		want           map[string]string
		expr           string
		wantBuildErr   bool
		wantRuntimeErr bool
	}{
		{
			name:  "ParseKv() test: valid string",
			value: "foo=bar",
			want:  map[string]string{"foo": "bar"},
			expr:  `ParseKV(value, out, "a")`,
		},
		{
			name:  "ParseKv() test: valid string",
			value: "foo=bar bar=foo",
			want:  map[string]string{"foo": "bar", "bar": "foo"},
			expr:  `ParseKV(value, out, "a")`,
		},
		{
			name:  "ParseKv() test: valid string",
			value: "foo=bar bar=foo foo=foo",
			want:  map[string]string{"foo": "foo", "bar": "foo"},
			expr:  `ParseKV(value, out, "a")`,
		},
		{
			name:  "ParseKV() test: quoted string",
			value: `foo="bar=toto"`,
			want:  map[string]string{"foo": "bar=toto"},
			expr:  `ParseKV(value, out, "a")`,
		},
		{
			name:  "ParseKV() test: empty unquoted string",
			value: `foo= bar=toto`,
			want:  map[string]string{"bar": "toto", "foo": ""},
			expr:  `ParseKV(value, out, "a")`,
		},
		{
			name:  "ParseKV() test: empty quoted string ",
			value: `foo="" bar=toto`,
			want:  map[string]string{"bar": "toto", "foo": ""},
			expr:  `ParseKV(value, out, "a")`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			outMap := make(map[string]any)
			env := map[string]any{
				"value": tc.value,
				"out":   outMap,
			}
			vm, err := expr.Compile(tc.expr, GetExprOptions(env)...)
			require.NoError(t, err)
			_, err = expr.Run(vm, env)
			require.NoError(t, err)
			assert.Equal(t, tc.want, outMap["a"])
		})
	}
}

func TestReplaceRegexp(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		name   string
		env    map[string]any
		code   string
		result string
		err    string
	}{
		{
			name: "ReplaceRegexp() test: replace first occurrence",
			env: map[string]any{
				"pattern": "foo",
				"source":  "foobar foobaz",
				"repl":    "qux",
			},
			code:   "ReplaceRegexp(pattern, source, repl)",
			result: "quxbar foobaz",
		},
		{
			name: "ReplaceRegexp() test: no match",
			env: map[string]any{
				"pattern": "xyz",
				"source":  "foobar foobaz",
				"repl":    "qux",
			},
			code:   "ReplaceRegexp(pattern, source, repl)",
			result: "foobar foobaz",
		},
		{
			name: "ReplaceRegexp() test: regex with special chars",
			env: map[string]any{
				"pattern": "\\d+",
				"source":  "abc123def456",
				"repl":    "X",
			},
			code:   "ReplaceRegexp(pattern, source, repl)",
			result: "abcXdef456",
		},
		{
			name: "ReplaceRegexp() test: case insensitive",
			env: map[string]any{
				"pattern": "(?i)FOO",
				"source":  "foobar FOOBAZ",
				"repl":    "qux",
			},
			code:   "ReplaceRegexp(pattern, source, repl)",
			result: "quxbar FOOBAZ",
		},
		{
			name: "ReplaceRegexp() test: invalid regex",
			env: map[string]any{
				"pattern": "[",
				"source":  "foobar",
				"repl":    "qux",
			},
			code: "ReplaceRegexp(pattern, source, repl)",
			err:  "error parsing regexp",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
			require.NoError(t, err)
			output, err := expr.Run(program, test.env)

			if test.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.result, output)
		})
	}
}

func TestReplaceAllRegex(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		name   string
		env    map[string]any
		code   string
		result string
		err    string
	}{
		{
			name: "ReplaceAllRegex() test: replace all occurrences",
			env: map[string]any{
				"pattern": "foo",
				"source":  "foobar foobaz",
				"repl":    "qux",
			},
			code:   "ReplaceAllRegex(pattern, source, repl)",
			result: "quxbar quxbaz",
		},
		{
			name: "ReplaceAllRegex() test: no match",
			env: map[string]any{
				"pattern": "xyz",
				"source":  "foobar foobaz",
				"repl":    "qux",
			},
			code:   "ReplaceAllRegex(pattern, source, repl)",
			result: "foobar foobaz",
		},
		{
			name: "ReplaceAllRegex() test: regex with special chars",
			env: map[string]any{
				"pattern": "\\d+",
				"source":  "abc123def456",
				"repl":    "X",
			},
			code:   "ReplaceAllRegex(pattern, source, repl)",
			result: "abcXdefX",
		},
		{
			name: "ReplaceAllRegex() test: case insensitive",
			env: map[string]any{
				"pattern": "(?i)FOO",
				"source":  "foobar FOOBAZ",
				"repl":    "qux",
			},
			code:   "ReplaceAllRegex(pattern, source, repl)",
			result: "quxbar quxBAZ",
		},
		{
			name: "ReplaceAllRegex() test: multiple matches with capture groups",
			env: map[string]any{
				"pattern": "(\\w+)@(\\w+)",
				"source":  "user1@domain1 user2@domain2",
				"repl":    "$1[at]$2",
			},
			code:   "ReplaceAllRegex(pattern, source, repl)",
			result: "user1[at]domain1 user2[at]domain2",
		},
		{
			name: "ReplaceAllRegex() test: invalid regex",
			env: map[string]any{
				"pattern": "[",
				"source":  "foobar",
				"repl":    "qux",
			},
			code: "ReplaceAllRegex(pattern, source, repl)",
			err:  "error parsing regexp",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
			require.NoError(t, err)
			output, err := expr.Run(program, test.env)

			if test.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.result, output)
		})
	}
}

func TestAnsiRegex(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		name   string
		env    map[string]any
		code   string
		result string
	}{
		{
			name:   "AnsiRegex() test: returns ANSI regex pattern",
			env:    map[string]any{},
			code:   "AnsiRegex()",
			result: `\x1b\[[0-9;]*m|\033\[[0-9;]*m`,
		},
		{
			name: "AnsiRegex() test: can be used with ReplaceAllRegex",
			env: map[string]any{
				"coloredText": "\x1b[31mHello\x1b[0m \x1b[32mWorld\x1b[0m",
			},
			code:   "ReplaceAllRegex(AnsiRegex(), coloredText, '')",
			result: "Hello World",
		},
		{
			name: "AnsiRegex() test: can be used with ReplaceRegexp (first occurrence only)",
			env: map[string]any{
				"coloredText": "\x1b[31mHello\x1b[0m \x1b[32mWorld\x1b[0m",
			},
			code:   "ReplaceRegexp(AnsiRegex(), coloredText, '')",
			result: "Hello\x1b[0m \x1b[32mWorld\x1b[0m",
		},
		{
			name: "AnsiRegex() test: handles complex ANSI sequences",
			env: map[string]any{
				"complexText": "\x1b[38;5;208mOrange\x1b[0m \x1b[38;5;119mLightGreen\x1b[0m",
			},
			code:   "ReplaceAllRegex(AnsiRegex(), complexText, '')",
			result: "Orange LightGreen",
		},
		{
			name: "AnsiRegex() test: handles background colors",
			env: map[string]any{
				"bgText": "\x1b[41mRed Background\x1b[0m \x1b[42mGreen Background\x1b[0m",
			},
			code:   "ReplaceAllRegex(AnsiRegex(), bgText, '')",
			result: "Red Background Green Background",
		},
		{
			name: "AnsiRegex() test: handles mixed hex and octal formats",
			env: map[string]any{
				"mixedText": "\x1b[31mRed\x1b[0m \033[32mGreen\033[0m \x1b[33mYellow\x1b[0m",
			},
			code:   "ReplaceAllRegex(AnsiRegex(), mixedText, '')",
			result: "Red Green Yellow",
		},
		{
			name: "AnsiRegex() test: handles both hex and octal formats",
			env: map[string]any{
				"bothFormats": "\x1b[31mRed\x1b[0m \033[32mGreen\033[0m \x1b[33mYellow\x1b[0m",
			},
			code:   "ReplaceAllRegex(AnsiRegex(), bothFormats, '')",
			result: "Red Green Yellow",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			program, err := expr.Compile(test.code, GetExprOptions(test.env)...)
			require.NoError(t, err)
			output, err := expr.Run(program, test.env)
			require.NoError(t, err)
			require.Equal(t, test.result, output)
		})
	}
}
