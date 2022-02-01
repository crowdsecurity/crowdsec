package exprhelpers

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"testing"

	"github.com/antonmedv/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	TestFolder = "tests"
)

func TestVisitor(t *testing.T) {
	if err := Init(); err != nil {
		log.Fatalf(err.Error())
	}

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
	clog := log.WithFields(log.Fields{
		"type": "test",
	})

	for _, test := range tests {
		compiledFilter, err := expr.Compile(test.filter, expr.Env(GetExprEnv(test.env)))
		if err != nil && test.err == nil {
			log.Fatalf("compile: %s", err.Error())
		}
		debugFilter, err := NewDebugger(test.filter, expr.Env(GetExprEnv(test.env)))
		if err != nil && test.err == nil {
			log.Fatalf("debug: %s", err.Error())
		}

		if compiledFilter != nil {
			result, err := expr.Run(compiledFilter, GetExprEnv(test.env))
			if err != nil && test.err == nil {
				log.Fatalf("run : %s", err.Error())
			}
			if isOk := assert.Equal(t, test.result, result); !isOk {
				t.Fatalf("test '%s' : NOK", test.filter)
			}
		}

		if debugFilter != nil {
			debugFilter.Run(clog, test.result, GetExprEnv(test.env))
		}
	}
}

func TestRegexpInFile(t *testing.T) {
	if err := Init(); err != nil {
		log.Fatalf(err.Error())
	}

	err := FileInit(TestFolder, "test_data_re.txt", "regex")
	if err != nil {
		log.Fatalf(err.Error())
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
		compiledFilter, err := expr.Compile(test.filter, expr.Env(GetExprEnv(map[string]interface{}{})))
		if err != nil {
			log.Fatalf(err.Error())
		}
		result, err := expr.Run(compiledFilter, GetExprEnv(map[string]interface{}{}))
		if err != nil {
			log.Fatalf(err.Error())
		}
		if isOk := assert.Equal(t, test.result, result); !isOk {
			t.Fatalf("test '%s' : NOK", test.name)
		}
	}
}

func TestFileInit(t *testing.T) {
	if err := Init(); err != nil {
		log.Fatalf(err.Error())
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
			log.Fatalf(err.Error())
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
	if err := Init(); err != nil {
		log.Fatalf(err.Error())
	}

	err := FileInit(TestFolder, "test_data.txt", "string")
	if err != nil {
		log.Fatalf(err.Error())
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
		compiledFilter, err := expr.Compile(test.filter, expr.Env(GetExprEnv(map[string]interface{}{})))
		if err != nil {
			log.Fatalf(err.Error())
		}
		result, err := expr.Run(compiledFilter, GetExprEnv(map[string]interface{}{}))
		if err != nil {
			log.Fatalf(err.Error())
		}
		if isOk := assert.Equal(t, test.result, result); !isOk {
			t.Fatalf("test '%s' : NOK", test.name)
		}
		log.Printf("test '%s' : OK", test.name)

	}
}

func TestIpInRange(t *testing.T) {
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
				"ip":        "192.168.0.1",
				"ipRange":   "192.168.0.0/24",
				"IpInRange": IpInRange,
			},
			code:   "IpInRange(ip, ipRange)",
			result: true,
			err:    "",
		},
		{
			name: "IpInRange() test: malformed IP",
			env: map[string]interface{}{
				"ip":        "192.168.0",
				"ipRange":   "192.168.0.0/24",
				"IpInRange": IpInRange,
			},
			code:   "IpInRange(ip, ipRange)",
			result: false,
			err:    "",
		},
		{
			name: "IpInRange() test: malformed IP range",
			env: map[string]interface{}{
				"ip":        "192.168.0.0/255",
				"ipRange":   "192.168.0.0/24",
				"IpInRange": IpInRange,
			},
			code:   "IpInRange(ip, ipRange)",
			result: false,
			err:    "",
		},
	}

	for _, test := range tests {
		program, err := expr.Compile(test.code, expr.Env(test.env))
		require.NoError(t, err)
		output, err := expr.Run(program, test.env)
		require.NoError(t, err)
		require.Equal(t, test.result, output)
		log.Printf("test '%s' : OK", test.name)
	}

}

func TestAtof(t *testing.T) {
	testFloat := "1.5"
	expectedFloat := 1.5

	if Atof(testFloat) != expectedFloat {
		t.Fatalf("Atof should returned 1.5 as a float")
	}

	log.Printf("test 'Atof()' : OK")

	//bad float
	testFloat = "1aaa.5"
	expectedFloat = 0.0

	if Atof(testFloat) != expectedFloat {
		t.Fatalf("Atof should returned a negative value (error) as a float got")
	}

	log.Printf("test 'Atof()' : OK")
}

func TestUpper(t *testing.T) {
	testStr := "test"
	expectedStr := "TEST"

	if Upper(testStr) != expectedStr {
		t.Fatalf("Upper() should returned test in upper case")
	}

	log.Printf("test 'Upper()' : OK")
}

func TestTimeNow(t *testing.T) {
	ti, err := time.Parse(time.RFC3339, TimeNow())
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
			result: map[string][]string{"a": []string{"1"}, "b": []string{"2"}},
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
			result: map[string][]string{"a": []string{"1"}, "b": []string{"2?"}},
			err:    "",
		},
		{
			name: "ParseUri() test: weird params",
			env: map[string]interface{}{
				"uri":      "/foo?&?&&&&?=123",
				"ParseUri": ParseUri,
			},
			code:   "ParseUri(uri)",
			result: map[string][]string{"?": []string{"", "123"}},
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
		program, err := expr.Compile(test.code, expr.Env(test.env))
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
		program, err := expr.Compile(test.code, expr.Env(test.env))
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
		program, err := expr.Compile(test.code, expr.Env(test.env))
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
		program, err := expr.Compile(test.code, expr.Env(test.env))
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
		program, err := expr.Compile(test.code, expr.Env(test.env))
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
		program, err := expr.Compile(test.code, expr.Env(test.env))
		require.NoError(t, err)
		output, err := expr.Run(program, test.env)
		require.NoError(t, err)
		require.Equal(t, test.result, output)
		log.Printf("test '%s' : OK", test.name)
	}
}
