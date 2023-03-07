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

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cstest"
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
	if err != nil {
		t.Fatal(err)
	}
	testDbClient, err := database.NewClient(&csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbName: "crowdsec",
		DbPath: dbPath.Name(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return testDbClient
}

func TestVisitor(t *testing.T) {
	if err := Init(nil); err != nil {
		log.Fatal(err)
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
			log.Fatalf("compile: %s", err)
		}
		debugFilter, err := NewDebugger(test.filter, expr.Env(GetExprEnv(test.env)))
		if err != nil && test.err == nil {
			log.Fatalf("debug: %s", err)
		}

		if compiledFilter != nil {
			result, err := expr.Run(compiledFilter, GetExprEnv(test.env))
			if err != nil && test.err == nil {
				log.Fatalf("run : %s", err)
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

func TestRegexpCacheBehavior(t *testing.T) {
	if err := Init(nil); err != nil {
		log.Fatal(err)
	}
	filename := "test_data_re.txt"
	err := FileInit(TestFolder, filename, "regex")
	if err != nil {
		log.Fatal(err)
	}
	//cache with no TTL
	if err := RegexpCacheInit(filename, types.DataSource{Type: "regex", Size: types.IntPtr(1)}); err != nil {
		log.Fatal(err)
	}
	ret := RegexpInFile("crowdsec", filename)
	assert.Equal(t, false, ret)
	assert.Equal(t, 1, dataFileRegexCache[filename].Len(false))
	ret = RegexpInFile("Crowdsec", filename)
	assert.Equal(t, true, ret)
	assert.Equal(t, 1, dataFileRegexCache[filename].Len(false))

	//cache with TTL
	ttl := 500 * time.Millisecond
	if err := RegexpCacheInit(filename, types.DataSource{Type: "regex", Size: types.IntPtr(2), TTL: &ttl}); err != nil {
		log.Fatal(err)
	}
	ret = RegexpInFile("crowdsec", filename)
	assert.Equal(t, false, ret)
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
		compiledFilter, err := expr.Compile(test.filter, expr.Env(GetExprEnv(map[string]interface{}{})))
		if err != nil {
			log.Fatal(err)
		}
		result, err := expr.Run(compiledFilter, GetExprEnv(map[string]interface{}{}))
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
		compiledFilter, err := expr.Compile(test.filter, expr.Env(GetExprEnv(map[string]interface{}{})))
		if err != nil {
			log.Fatal(err)
		}
		result, err := expr.Run(compiledFilter, GetExprEnv(map[string]interface{}{}))
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

func TestIpToRange(t *testing.T) {
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
				"ip":        "192.168.1.1",
				"netmask":   "16",
				"IpToRange": IpToRange,
			},
			code:   "IpToRange(ip, netmask)",
			result: "192.168.0.0/16",
			err:    "",
		},
		{
			name: "IpToRange() test: IPv6",
			env: map[string]interface{}{
				"ip":        "2001:db8::1",
				"netmask":   "/64",
				"IpToRange": IpToRange,
			},
			code:   "IpToRange(ip, netmask)",
			result: "2001:db8::/64",
			err:    "",
		},
		{
			name: "IpToRange() test: malformed netmask",
			env: map[string]interface{}{
				"ip":        "192.168.0.1",
				"netmask":   "test",
				"IpToRange": IpToRange,
			},
			code:   "IpToRange(ip, netmask)",
			result: "",
			err:    "",
		},
		{
			name: "IpToRange() test: malformed IP",
			env: map[string]interface{}{
				"ip":        "a.b.c.d",
				"netmask":   "24",
				"IpToRange": IpToRange,
			},
			code:   "IpToRange(ip, netmask)",
			result: "",
			err:    "",
		},
		{
			name: "IpToRange() test: too high netmask",
			env: map[string]interface{}{
				"ip":        "192.168.1.1",
				"netmask":   "35",
				"IpToRange": IpToRange,
			},
			code:   "IpToRange(ip, netmask)",
			result: "",
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
		t.Fatalf("Atof should return 1.5 as a float")
	}

	log.Printf("test 'Atof()' : OK")

	//bad float
	testFloat = "1aaa.5"
	expectedFloat = 0.0

	if Atof(testFloat) != expectedFloat {
		t.Fatalf("Atof should return a negative value (error) as a float got")
	}

	log.Printf("test 'Atof()' : OK")
}

func TestUpper(t *testing.T) {
	testStr := "test"
	expectedStr := "TEST"

	if Upper(testStr) != expectedStr {
		t.Fatalf("Upper() should return test in upper case")
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
				"GetDecisionsCount": GetDecisionsCount,
				"sprintf":           fmt.Sprintf,
			},
			code:   "sprintf('%d', GetDecisionsCount(Alert.GetValue()))",
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
				"GetDecisionsCount": GetDecisionsCount,
				"sprintf":           fmt.Sprintf,
			},
			code:   "sprintf('%d', GetDecisionsCount(Alert.GetValue()))",
			result: "0",
			err:    "",
		},
	}

	for _, test := range tests {
		program, err := expr.Compile(test.code, expr.Env(GetExprEnv(test.env)))
		require.NoError(t, err)
		output, err := expr.Run(program, GetExprEnv(test.env))
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
				"GetDecisionsSinceCount": GetDecisionsSinceCount,
				"sprintf":                fmt.Sprintf,
			},
			code:   "sprintf('%d', GetDecisionsSinceCount(Alert.GetValue(), '25h'))",
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
				"GetDecisionsSinceCount": GetDecisionsSinceCount,
				"sprintf":                fmt.Sprintf,
			},
			code:   "sprintf('%d', GetDecisionsSinceCount(Alert.GetValue(), '1h'))",
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
				"GetDecisionsSinceCount": GetDecisionsSinceCount,
				"sprintf":                fmt.Sprintf,
			},
			code:   "sprintf('%d', GetDecisionsSinceCount(Alert.GetValue(), '1h'))",
			result: "0",
			err:    "",
		},
	}

	for _, test := range tests {
		program, err := expr.Compile(test.code, expr.Env(GetExprEnv(test.env)))
		require.NoError(t, err)
		output, err := expr.Run(program, GetExprEnv(test.env))
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
			require.WithinDuration(t, tc.expected, output, time.Second)
		})
	}
}

func TestIsIp(t *testing.T) {
	tests := []struct {
		name     string
		method   func(string) bool
		value    string
		expected bool
	}{
		{
			name:     "IsIPV4() test: valid IPv4",
			method:   IsIPV4,
			value:    "1.2.3.4",
			expected: true,
		},
		{
			name:     "IsIPV6() test: valid IPv6",
			method:   IsIPV6,
			value:    "1.2.3.4",
			expected: false,
		},
		{
			name:     "IsIPV6() test: valid IPv6",
			method:   IsIPV6,
			value:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expected: true,
		},
		{
			name:     "IsIPV4() test: valid IPv6",
			method:   IsIPV4,
			value:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expected: false,
		},
		{
			name:     "IsIP() test: invalid IP",
			method:   IsIP,
			value:    "foo.bar",
			expected: false,
		},
		{
			name:     "IsIP() test: valid IPv4",
			method:   IsIP,
			value:    "1.2.3.4",
			expected: true,
		},
		{
			name:     "IsIP() test: valid IPv6",
			method:   IsIP,
			value:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expected: true,
		},
		{
			name:     "IsIPV4() test: invalid IPv4",
			method:   IsIPV4,
			value:    "foo.bar",
			expected: false,
		},
		{
			name:     "IsIPV6() test: invalid IPv6",
			method:   IsIPV6,
			value:    "foo.bar",
			expected: false,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			output := tc.method(tc.value)
			require.Equal(t, tc.expected, output)
		})
	}
}
