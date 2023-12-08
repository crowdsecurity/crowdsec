package exprhelpers

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/antonmedv/expr"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

var (
	TestFolder = "tests"
)

func getDBClient(t *testing.T) *database.Client {
	t.Helper()
	dbPath, err := os.CreateTemp("", "*sqlite")
	require.NoError(t, err)

	testDbClient, err := database.NewClient(&csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbName: "crowdsec",
		DbPath: dbPath.Name(),
	})
	require.NoError(t, err)

	return testDbClient
}

func TestVisitor(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		name   string
		filter string
		result bool
		env    map[string]interface{}
		err    error
	}{
		{
			name:   "debug : no variable",
			filter: "'crowdsec' startsWith 'crowdse'",
			result: true,
			err:    nil,
			env:    map[string]interface{}{},
		},
		{
			name:   "debug : simple variable",
			filter: "'crowdsec' startsWith static_one && 1 == 1",
			result: true,
			err:    nil,
			env:    map[string]interface{}{"static_one": string("crowdse")},
		},
		{
			name:   "debug : simple variable re-used",
			filter: "static_one.foo == 'bar' && static_one.foo != 'toto'",
			result: true,
			err:    nil,
			env:    map[string]interface{}{"static_one": map[string]string{"foo": "bar"}},
		},
		{
			name:   "debug : can't compile",
			filter: "static_one.foo.toto == 'lol'",
			result: false,
			err:    fmt.Errorf("bad syntax"),
			env:    map[string]interface{}{"static_one": map[string]string{"foo": "bar"}},
		},
		{
			name:   "debug : can't compile #2",
			filter: "static_one.f!oo.to/to == 'lol'",
			result: false,
			err:    fmt.Errorf("bad syntax"),
			env:    map[string]interface{}{"static_one": map[string]string{"foo": "bar"}},
		},
		{
			name:   "debug : can't compile #3",
			filter: "",
			result: false,
			err:    fmt.Errorf("bad syntax"),
			env:    map[string]interface{}{"static_one": map[string]string{"foo": "bar"}},
		},
	}

	log.SetLevel(log.DebugLevel)

	for _, test := range tests {
		compiledFilter, err := expr.Compile(test.filter, GetExprOptions(test.env)...)
		if err != nil && test.err == nil {
			log.Fatalf("compile: %s", err)
		}

		if compiledFilter != nil {
			result, err := expr.Run(compiledFilter, test.env)
			if err != nil && test.err == nil {
				log.Fatalf("run : %s", err)
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
		env := map[string]interface{}{
			"pattern": test.glob,
			"name":    test.val,
		}
		vm, err := expr.Compile(test.expr, GetExprOptions(env)...)
		if err != nil {
			t.Fatalf("pattern:%s val:%s NOK %s", test.glob, test.val, err)
		}
		ret, err := expr.Run(vm, env)
		assert.NoError(t, err)
		if isOk := assert.Equal(t, test.ret, ret); !isOk {
			t.Fatalf("pattern:%s val:%s NOK %t !=  %t", test.glob, test.val, ret, test.ret)
		}
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
			env := map[string]interface{}{
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
				assert.NoError(t, err)
				assert.Equal(t, test.dist, ret)
			} else {
				assert.NotNil(t, err)
			}
		})
	}
}

func TestRegexpCacheBehavior(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	filename := "test_data_re.txt"
	err = FileInit(TestFolder, filename, "regex")
	require.NoError(t, err)

	//cache with no TTL
	err = RegexpCacheInit(filename, types.DataSource{Type: "regex", Size: ptr.Of(1)})
	require.NoError(t, err)

	ret, _ := RegexpInFile("crowdsec", filename)
	assert.False(t, ret.(bool))
	assert.Equal(t, 1, dataFileRegexCache[filename].Len(false))

	ret, _ = RegexpInFile("Crowdsec", filename)
	assert.True(t, ret.(bool))
	assert.Equal(t, 1, dataFileRegexCache[filename].Len(false))

	//cache with TTL
	ttl := 500 * time.Millisecond
	err = RegexpCacheInit(filename, types.DataSource{Type: "regex", Size: ptr.Of(2), TTL: &ttl})
	require.NoError(t, err)

	ret, _ = RegexpInFile("crowdsec", filename)
	assert.False(t, ret.(bool))
	assert.Equal(t, 1, dataFileRegexCache[filename].Len(true))

	time.Sleep(1 * time.Second)
	assert.Equal(t, 0, dataFileRegexCache[filename].Len(true))
}

func TestRegexpInFile(t *testing.T) {
	if err := Init(nil); err != nil {
		log.Fatal(err)
	}

	err := FileInit(TestFolder, "test_data_re.txt", "regex")
	if err != nil {
		log.Fatal(err)
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
		compiledFilter, err := expr.Compile(test.filter, GetExprOptions(map[string]interface{}{})...)
		if err != nil {
			log.Fatal(err)
		}
		result, err := expr.Run(compiledFilter, map[string]interface{}{})
		if err != nil {
			log.Fatal(err)
		}
		if isOk := assert.Equal(t, test.result, result); !isOk {
			t.Fatalf("test '%s' : NOK", test.name)
		}
	}
}

func TestFileInit(t *testing.T) {
	if err := Init(nil); err != nil {
		log.Fatal(err)
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
		err := FileInit(TestFolder, test.filename, test.types)
		if err != nil {
			log.Fatal(err)
		}
		if test.types == "string" {
			if _, ok := dataFile[test.filename]; !ok {
				t.Fatalf("test '%s' : NOK", test.name)
			}
			if isOk := assert.Equal(t, test.result, len(dataFile[test.filename])); !isOk {
				t.Fatalf("test '%s' : NOK", test.name)
			}
		} else if test.types == "regex" {
			if _, ok := dataFileRegex[test.filename]; !ok {
				t.Fatalf("test '%s' : NOK", test.name)
			}
			if isOk := assert.Equal(t, test.result, len(dataFileRegex[test.filename])); !isOk {
				t.Fatalf("test '%s' : NOK", test.name)
			}
		} else {
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
		log.Fatal(err)
	}

	err := FileInit(TestFolder, "test_data.txt", "string")
	if err != nil {
		log.Fatal(err)
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
		compiledFilter, err := expr.Compile(test.filter, GetExprOptions(map[string]interface{}{})...)
		if err != nil {
			log.Fatal(err)
		}
		result, err := expr.Run(compiledFilter, map[string]interface{}{})
		if err != nil {
			log.Fatal(err)
		}
		if isOk := assert.Equal(t, test.result, result); !isOk {
			t.Fatalf("test '%s' : NOK", test.name)
		}
		log.Printf("test '%s' : OK", test.name)

	}
}

func TestIpInRange(t *testing.T) {
	err := Init(nil)
	assert.NoError(t, err)
	tests := []struct {
		name   string
		env    map[string]interface{}
		code   string
		result bool
		err    string
	}{
		{
			name: "IpInRange() test: basic test",
			env: map[string]interface{}{
				"ip":      "192.168.0.1",
				"ipRange": "192.168.0.0/24",
			},
			code:   "IpInRange(ip, ipRange)",
			result: true,
			err:    "",
		},
		{
			name: "IpInRange() test: malformed IP",
			env: map[string]interface{}{
				"ip":      "192.168.0",
				"ipRange": "192.168.0.0/24",
			},
			code:   "IpInRange(ip, ipRange)",
			result: false,
			err:    "",
		},
		{
			name: "IpInRange() test: malformed IP range",
			env: map[string]interface{}{
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
	assert.NoError(t, err)
	tests := []struct {
		name   string
		env    map[string]interface{}
		code   string
		result string
		err    string
	}{
		{
			name: "IpToRange() test: IPv4",
			env: map[string]interface{}{
				"ip":      "192.168.1.1",
				"netmask": "16",
			},
			code:   "IpToRange(ip, netmask)",
			result: "192.168.0.0/16",
			err:    "",
		},
		{
			name: "IpToRange() test: IPv6",
			env: map[string]interface{}{
				"ip":      "2001:db8::1",
				"netmask": "/64",
			},
			code:   "IpToRange(ip, netmask)",
			result: "2001:db8::/64",
			err:    "",
		},
		{
			name: "IpToRange() test: malformed netmask",
			env: map[string]interface{}{
				"ip":      "192.168.0.1",
				"netmask": "test",
			},
			code:   "IpToRange(ip, netmask)",
			result: "",
			err:    "",
		},
		{
			name: "IpToRange() test: malformed IP",
			env: map[string]interface{}{
				"ip":      "a.b.c.d",
				"netmask": "24",
			},
			code:   "IpToRange(ip, netmask)",
			result: "",
			err:    "",
		},
		{
			name: "IpToRange() test: too high netmask",
			env: map[string]interface{}{
				"ip":      "192.168.1.1",
				"netmask": "35",
			},
			code:   "IpToRange(ip, netmask)",
			result: "",
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

func TestAtof(t *testing.T) {

	err := Init(nil)
	assert.NoError(t, err)

	tests := []struct {
		name   string
		env    map[string]interface{}
		code   string
		result float64
	}{
		{
			name: "Atof() test: basic test",
			env: map[string]interface{}{
				"testFloat": "1.5",
			},
			code:   "Atof(testFloat)",
			result: 1.5,
		},
		{
			name: "Atof() test: bad float",
			env: map[string]interface{}{
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
		require.Equal(t, test.result, output)
	}
}

func TestUpper(t *testing.T) {
	testStr := "test"
	expectedStr := "TEST"

	env := map[string]interface{}{
		"testStr": testStr,
	}

	err := Init(nil)
	assert.NoError(t, err)
	vm, err := expr.Compile("Upper(testStr)", GetExprOptions(env)...)
	assert.NoError(t, err)

	out, err := expr.Run(vm, env)

	assert.NoError(t, err)
	v, ok := out.(string)
	if !ok {
		t.Fatalf("Upper() should return a string")
	}

	if v != expectedStr {
		t.Fatalf("Upper() should return test in upper case")
	}
}

func TestTimeNow(t *testing.T) {
	now, _ := TimeNow()
	ti, err := time.Parse(time.RFC3339, now.(string))
	if err != nil {
		t.Fatalf("Error parsing the return value of TimeNow: %s", err)
	}

	if -1*time.Until(ti) > time.Second {
		t.Fatalf("TimeNow func should return time.Now().UTC()")
	}
	log.Printf("test 'TimeNow()' : OK")
}

func TestParseUri(t *testing.T) {
	tests := []struct {
		name   string
		env    map[string]interface{}
		code   string
		result map[string][]string
		err    string
	}{
		{
			name: "ParseUri() test: basic test",
			env: map[string]interface{}{
				"uri":      "/foo?a=1&b=2",
				"ParseUri": ParseUri,
			},
			code:   "ParseUri(uri)",
			result: map[string][]string{"a": {"1"}, "b": {"2"}},
			err:    "",
		},
		{
			name: "ParseUri() test: no param",
			env: map[string]interface{}{
				"uri":      "/foo",
				"ParseUri": ParseUri,
			},
			code:   "ParseUri(uri)",
			result: map[string][]string{},
			err:    "",
		},
		{
			name: "ParseUri() test: extra question mark",
			env: map[string]interface{}{
				"uri":      "/foo?a=1&b=2?",
				"ParseUri": ParseUri,
			},
			code:   "ParseUri(uri)",
			result: map[string][]string{"a": {"1"}, "b": {"2?"}},
			err:    "",
		},
		{
			name: "ParseUri() test: weird params",
			env: map[string]interface{}{
				"uri":      "/foo?&?&&&&?=123",
				"ParseUri": ParseUri,
			},
			code:   "ParseUri(uri)",
			result: map[string][]string{"?": {"", "123"}},
			err:    "",
		},
		{
			name: "ParseUri() test: bad encoding",
			env: map[string]interface{}{
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
		env    map[string]interface{}
		code   string
		result string
		err    string
	}{
		{
			name: "QueryEscape() test: basic test",
			env: map[string]interface{}{
				"uri":         "/foo?a=1&b=2",
				"QueryEscape": QueryEscape,
			},
			code:   "QueryEscape(uri)",
			result: "%2Ffoo%3Fa%3D1%26b%3D2",
			err:    "",
		},
		{
			name: "QueryEscape() test: basic test",
			env: map[string]interface{}{
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
		env    map[string]interface{}
		code   string
		result string
		err    string
	}{
		{
			name: "PathEscape() test: basic test",
			env: map[string]interface{}{
				"uri":        "/foo?a=1&b=2",
				"PathEscape": PathEscape,
			},
			code:   "PathEscape(uri)",
			result: "%2Ffoo%3Fa=1&b=2",
			err:    "",
		},
		{
			name: "PathEscape() test: basic test with more special chars",
			env: map[string]interface{}{
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
		env    map[string]interface{}
		code   string
		result string
		err    string
	}{
		{
			name: "PathUnescape() test: basic test",
			env: map[string]interface{}{
				"uri":          "%2Ffoo%3Fa=1&b=%3C%3E%27%22",
				"PathUnescape": PathUnescape,
			},
			code:   "PathUnescape(uri)",
			result: "/foo?a=1&b=<>'\"",
			err:    "",
		},
		{
			name: "PathUnescape() test: basic test with more special chars",
			env: map[string]interface{}{
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
		env    map[string]interface{}
		code   string
		result string
		err    string
	}{
		{
			name: "QueryUnescape() test: basic test",
			env: map[string]interface{}{
				"uri":           "%2Ffoo%3Fa=1&b=%3C%3E%27%22",
				"QueryUnescape": QueryUnescape,
			},
			code:   "QueryUnescape(uri)",
			result: "/foo?a=1&b=<>'\"",
			err:    "",
		},
		{
			name: "QueryUnescape() test: basic test with more special chars",
			env: map[string]interface{}{
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
		env    map[string]interface{}
		code   string
		result string
		err    string
	}{
		{
			name: "Lower() test: basic test",
			env: map[string]interface{}{
				"name":  "ABCDEFG",
				"Lower": Lower,
			},
			code:   "Lower(name)",
			result: "abcdefg",
			err:    "",
		},
		{
			name: "Lower() test: basic test with more special chars",
			env: map[string]interface{}{
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
	var err error
	var start_ip, start_sfx, end_ip, end_sfx int64
	var ip_sz int
	existingIP := "1.2.3.4"
	unknownIP := "1.2.3.5"
	ip_sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(existingIP)
	if err != nil {
		t.Errorf("unable to convert '%s' to int: %s", existingIP, err)
	}
	// Add sample data to DB
	dbClient = getDBClient(t)

	decision := dbClient.Ent.Decision.Create().
		SetUntil(time.Now().Add(time.Hour)).
		SetScenario("crowdsec/test").
		SetStartIP(start_ip).
		SetStartSuffix(start_sfx).
		SetEndIP(end_ip).
		SetEndSuffix(end_sfx).
		SetIPSize(int64(ip_sz)).
		SetType("ban").
		SetScope("IP").
		SetValue(existingIP).
		SetOrigin("CAPI").
		SaveX(context.Background())

	if decision == nil {
		assert.Error(t, errors.Errorf("Failed to create sample decision"))
	}

	err = Init(dbClient)
	assert.NoError(t, err)

	tests := []struct {
		name   string
		env    map[string]interface{}
		code   string
		result string
		err    string
	}{
		{
			name: "GetDecisionsCount() test: existing IP count",
			env: map[string]interface{}{
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
			env: map[string]interface{}{
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
	var err error
	var start_ip, start_sfx, end_ip, end_sfx int64
	var ip_sz int
	existingIP := "1.2.3.4"
	unknownIP := "1.2.3.5"
	ip_sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(existingIP)
	if err != nil {
		t.Errorf("unable to convert '%s' to int: %s", existingIP, err)
	}
	// Add sample data to DB
	dbClient = getDBClient(t)

	decision := dbClient.Ent.Decision.Create().
		SetUntil(time.Now().Add(time.Hour)).
		SetScenario("crowdsec/test").
		SetStartIP(start_ip).
		SetStartSuffix(start_sfx).
		SetEndIP(end_ip).
		SetEndSuffix(end_sfx).
		SetIPSize(int64(ip_sz)).
		SetType("ban").
		SetScope("IP").
		SetValue(existingIP).
		SetOrigin("CAPI").
		SaveX(context.Background())
	if decision == nil {
		assert.Error(t, errors.Errorf("Failed to create sample decision"))
	}
	decision2 := dbClient.Ent.Decision.Create().
		SetCreatedAt(time.Now().AddDate(0, 0, -1)).
		SetUntil(time.Now().AddDate(0, 0, -1)).
		SetScenario("crowdsec/test").
		SetStartIP(start_ip).
		SetStartSuffix(start_sfx).
		SetEndIP(end_ip).
		SetEndSuffix(end_sfx).
		SetIPSize(int64(ip_sz)).
		SetType("ban").
		SetScope("IP").
		SetValue(existingIP).
		SetOrigin("CAPI").
		SaveX(context.Background())
	if decision2 == nil {
		assert.Error(t, errors.Errorf("Failed to create sample decision"))
	}

	err = Init(dbClient)
	assert.NoError(t, err)

	tests := []struct {
		name   string
		env    map[string]interface{}
		code   string
		result string
		err    string
	}{
		{
			name: "GetDecisionsSinceCount() test: existing IP count since more than 1 day",
			env: map[string]interface{}{
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
			env: map[string]interface{}{
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
			env: map[string]interface{}{
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

func TestParseUnixTime(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		expected    time.Time
		expectedErr string
	}{
		{
			name:     "ParseUnix() test: valid value with milli",
			value:    "1672239773.3590894",
			expected: time.Date(2022, 12, 28, 15, 02, 53, 0, time.UTC),
		},
		{
			name:     "ParseUnix() test: valid value without milli",
			value:    "1672239773",
			expected: time.Date(2022, 12, 28, 15, 02, 53, 0, time.UTC),
		},
		{
			name:        "ParseUnix() test: invalid input",
			value:       "AbcDefG!#",
			expected:    time.Time{},
			expectedErr: "unable to parse AbcDefG!# as unix timestamp",
		},
		{
			name:        "ParseUnix() test: negative value",
			value:       "-1000",
			expected:    time.Time{},
			expectedErr: "unable to parse -1000 as unix timestamp",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			output, err := ParseUnixTime(tc.value)
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			if tc.expectedErr != "" {
				return
			}
			require.WithinDuration(t, tc.expected, output.(time.Time), time.Second)
		})
	}
}

func TestIsIp(t *testing.T) {
	if err := Init(nil); err != nil {
		log.Fatal(err)
	}
	tests := []struct {
		name             string
		expr             string
		value            string
		expected         bool
		expectedBuildErr bool
	}{
		{
			name:     "IsIPV4() test: valid IPv4",
			expr:     `IsIPV4(value)`,
			value:    "1.2.3.4",
			expected: true,
		},
		{
			name:     "IsIPV6() test: valid IPv6",
			expr:     `IsIPV6(value)`,
			value:    "1.2.3.4",
			expected: false,
		},
		{
			name:     "IsIPV6() test: valid IPv6",
			expr:     `IsIPV6(value)`,
			value:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expected: true,
		},
		{
			name:     "IsIPV4() test: valid IPv6",
			expr:     `IsIPV4(value)`,
			value:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expected: false,
		},
		{
			name:     "IsIP() test: invalid IP",
			expr:     `IsIP(value)`,
			value:    "foo.bar",
			expected: false,
		},
		{
			name:     "IsIP() test: valid IPv4",
			expr:     `IsIP(value)`,
			value:    "1.2.3.4",
			expected: true,
		},
		{
			name:     "IsIP() test: valid IPv6",
			expr:     `IsIP(value)`,
			value:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expected: true,
		},
		{
			name:     "IsIPV4() test: invalid IPv4",
			expr:     `IsIPV4(value)`,
			value:    "foo.bar",
			expected: false,
		},
		{
			name:     "IsIPV6() test: invalid IPv6",
			expr:     `IsIPV6(value)`,
			value:    "foo.bar",
			expected: false,
		},
		{
			name:             "IsIPV4() test: invalid type",
			expr:             `IsIPV4(42)`,
			value:            "",
			expected:         false,
			expectedBuildErr: true,
		},
		{
			name:             "IsIP() test: invalid type",
			expr:             `IsIP(42)`,
			value:            "",
			expected:         false,
			expectedBuildErr: true,
		},
		{
			name:             "IsIPV6() test: invalid type",
			expr:             `IsIPV6(42)`,
			value:            "",
			expected:         false,
			expectedBuildErr: true,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			vm, err := expr.Compile(tc.expr, GetExprOptions(map[string]interface{}{"value": tc.value})...)
			if tc.expectedBuildErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			output, err := expr.Run(vm, map[string]interface{}{"value": tc.value})
			assert.NoError(t, err)
			assert.IsType(t, tc.expected, output)
			assert.Equal(t, tc.expected, output.(bool))
		})
	}
}

func TestToString(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)
	tests := []struct {
		name     string
		value    interface{}
		expected string
		expr     string
	}{
		{
			name:     "ToString() test: valid string",
			value:    "foo",
			expected: "foo",
			expr:     `ToString(value)`,
		},
		{
			name:     "ToString() test: valid string",
			value:    interface{}("foo"),
			expected: "foo",
			expr:     `ToString(value)`,
		},
		{
			name:     "ToString() test: invalid type",
			value:    1,
			expected: "",
			expr:     `ToString(value)`,
		},
		{
			name:     "ToString() test: invalid type 2",
			value:    interface{}(nil),
			expected: "",
			expr:     `ToString(value)`,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			vm, err := expr.Compile(tc.expr, GetExprOptions(map[string]interface{}{"value": tc.value})...)
			assert.NoError(t, err)
			output, err := expr.Run(vm, map[string]interface{}{"value": tc.value})
			assert.NoError(t, err)
			require.Equal(t, tc.expected, output)
		})
	}
}

func TestB64Decode(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		name               string
		value              interface{}
		expected           string
		expr               string
		expectedBuildErr   bool
		expectedRuntimeErr bool
	}{
		{
			name:             "B64Decode() test: valid string",
			value:            "Zm9v",
			expected:         "foo",
			expr:             `B64Decode(value)`,
			expectedBuildErr: false,
		},
		{
			name:               "B64Decode() test: invalid string",
			value:              "foo",
			expected:           "",
			expr:               `B64Decode(value)`,
			expectedBuildErr:   false,
			expectedRuntimeErr: true,
		},
		{
			name:             "B64Decode() test: invalid type",
			value:            1,
			expected:         "",
			expr:             `B64Decode(value)`,
			expectedBuildErr: true,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			vm, err := expr.Compile(tc.expr, GetExprOptions(map[string]interface{}{"value": tc.value})...)
			if tc.expectedBuildErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			output, err := expr.Run(vm, map[string]interface{}{"value": tc.value})
			if tc.expectedRuntimeErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			require.Equal(t, tc.expected, output)
		})
	}
}

func TestParseKv(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		name               string
		value              string
		expected           map[string]string
		expr               string
		expectedBuildErr   bool
		expectedRuntimeErr bool
	}{
		{
			name:     "ParseKv() test: valid string",
			value:    "foo=bar",
			expected: map[string]string{"foo": "bar"},
			expr:     `ParseKV(value, out, "a")`,
		},
		{
			name:     "ParseKv() test: valid string",
			value:    "foo=bar bar=foo",
			expected: map[string]string{"foo": "bar", "bar": "foo"},
			expr:     `ParseKV(value, out, "a")`,
		},
		{
			name:     "ParseKv() test: valid string",
			value:    "foo=bar bar=foo foo=foo",
			expected: map[string]string{"foo": "foo", "bar": "foo"},
			expr:     `ParseKV(value, out, "a")`,
		},
		{
			name:     "ParseKV() test: quoted string",
			value:    `foo="bar=toto"`,
			expected: map[string]string{"foo": "bar=toto"},
			expr:     `ParseKV(value, out, "a")`,
		},
		{
			name:     "ParseKV() test: empty unquoted string",
			value:    `foo= bar=toto`,
			expected: map[string]string{"bar": "toto", "foo": ""},
			expr:     `ParseKV(value, out, "a")`,
		},
		{
			name:     "ParseKV() test: empty quoted string ",
			value:    `foo="" bar=toto`,
			expected: map[string]string{"bar": "toto", "foo": ""},
			expr:     `ParseKV(value, out, "a")`,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			outMap := make(map[string]interface{})
			env := map[string]interface{}{
				"value": tc.value,
				"out":   outMap,
			}
			vm, err := expr.Compile(tc.expr, GetExprOptions(env)...)
			assert.NoError(t, err)
			_, err = expr.Run(vm, env)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, outMap["a"])
		})
	}
}
