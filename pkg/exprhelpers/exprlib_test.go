package exprhelpers

import (
	"log"
	"testing"

	"github.com/antonmedv/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	TestFolder = "tests"
)

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

func TestFile(t *testing.T) {
	if err := Init(); err != nil {
		log.Fatalf(err.Error())
	}

	err := FileInit(TestFolder, "test_data.txt", "")
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
}

func TestUpper(t *testing.T) {
	testStr := "test"
	expectedStr := "TEST"

	if Upper(testStr) != expectedStr {
		t.Fatalf("Upper() should returned 1.5 as a float")
	}

	log.Printf("test 'Upper()' : OK")
}
