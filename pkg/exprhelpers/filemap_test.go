package exprhelpers

import (
	"fmt"
	"testing"

	"github.com/expr-lang/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileInitMap(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	err = FileInit("testdata", "test_data_map.json", "map")
	require.NoError(t, err)

	entry, ok := dataFileMap["test_data_map.json"]
	require.True(t, ok, "test_data_map.json should be loaded")
	assert.Len(t, entry.rows, 9, "should have 9 rows (6 contains + 1 equals + 2 regex, skipping comment and empty line)")

	// Verify a specific contains row
	assert.Equal(t, "/tmui/", entry.rows[0]["pattern"])
	assert.Equal(t, "F5", entry.rows[0]["tag"])
	assert.Equal(t, "contains", entry.rows[0]["type"])

	// Verify equals row
	assert.Equal(t, "/specific/endpoint.php", entry.rows[6]["pattern"])
	assert.Equal(t, "SpecificApp", entry.rows[6]["tag"])
	assert.Equal(t, "equals", entry.rows[6]["type"])

	// Verify regex-typed row
	assert.Equal(t, "regex", entry.rows[7]["type"])
	assert.Equal(t, "WordPress-Plugin", entry.rows[7]["tag"])
}

func TestFileInitMapInvalidJSON(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	err = FileInit("testdata", "test_data_map_invalid.json", "map")
	require.Error(t, err, "should fail on invalid JSON line")
	assert.Contains(t, err.Error(), "failed to parse JSON line")
}

func TestFileInitMapMissingType(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	err = FileInit("testdata", "test_data_map_no_type.json", "map")
	require.Error(t, err, "should fail when type field is missing")
	assert.Contains(t, err.Error(), "missing mandatory 'type' field")
}

func TestFileInitMapUnknownType(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	err = FileInit("testdata", "test_data_map_bad_type.json", "map")
	require.Error(t, err, "should fail on unknown type value")
	assert.Contains(t, err.Error(), "unknown entry type 'foobar'")
}

func TestFileInitMapMissingPattern(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	err = FileInit("testdata", "test_data_map_no_pattern.json", "map")
	require.Error(t, err, "should fail when pattern field is missing")
	assert.Contains(t, err.Error(), "missing mandatory 'pattern' field")
}

func TestFileInitMapMissingTag(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	err = FileInit("testdata", "test_data_map_no_tag.json", "map")
	require.Error(t, err, "should fail when tag field is missing")
	assert.Contains(t, err.Error(), "missing mandatory 'tag' field")
}

func TestFileInitMapAlreadyLoaded(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	err = FileInit("testdata", "test_data_map.json", "map")
	require.NoError(t, err)

	// Loading again should be a no-op
	err = FileInit("testdata", "test_data_map.json", "map")
	require.NoError(t, err)
}

func TestFileInitMapComments(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	err = FileInit("testdata", "test_data_map.json", "map")
	require.NoError(t, err)

	entry := dataFileMap["test_data_map.json"]
	// No row should contain a comment marker
	for _, row := range entry.rows {
		for _, v := range row {
			assert.NotContains(t, v, "# this is a comment")
		}
	}
}

func TestExistsInFileMapsMap(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	ok, err := existsInFileMaps("test_data_map.json", "map")
	require.NoError(t, err)
	assert.False(t, ok, "should not exist before loading")

	err = FileInit("testdata", "test_data_map.json", "map")
	require.NoError(t, err)

	ok, err = existsInFileMaps("test_data_map.json", "map")
	require.NoError(t, err)
	assert.True(t, ok, "should exist after loading")
}

func TestFileMapHelper(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	err = FileInit("testdata", "test_data_map.json", "map")
	require.NoError(t, err)

	env := map[string]any{}
	compiledFilter, err := expr.Compile(`FileMap("test_data_map.json")`, GetExprOptions(env)...)
	require.NoError(t, err)

	result, err := expr.Run(compiledFilter, env)
	require.NoError(t, err)

	rows, ok := result.([]map[string]string)
	require.True(t, ok, "FileMap should return []map[string]string")
	assert.Len(t, rows, 9)
	assert.Equal(t, "F5", rows[0]["tag"])
}

func TestFileMapHelperMissingFile(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	env := map[string]any{}
	compiledFilter, err := expr.Compile(`FileMap("nonexistent.json")`, GetExprOptions(env)...)
	require.NoError(t, err)

	result, err := expr.Run(compiledFilter, env)
	require.NoError(t, err)

	rows, ok := result.([]map[string]string)
	require.True(t, ok)
	assert.Empty(t, rows)
}

func TestLookupFileContainsMatch(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	err = FileInit("testdata", "test_data_map.json", "map")
	require.NoError(t, err)

	tests := []struct {
		name     string
		haystack string
		expected string
	}{
		{
			name:     "match F5 tmui",
			haystack: "/admin/tmui/login.jsp",
			expected: "F5",
		},
		{
			name:     "match MikroTik webfig",
			haystack: "/webfig/winbox",
			expected: "MikroTik",
		},
		{
			name:     "match OpenWrt luci",
			haystack: "/cgi-bin/luci/admin",
			expected: "OpenWrt",
		},
		{
			name:     "match Generic .env",
			haystack: "/.env",
			expected: "Generic",
		},
		{
			name:     "match WordPress wp-admin",
			haystack: "/wp-admin/options.php",
			expected: "WordPress",
		},
		{
			name:     "no match",
			haystack: "/normal/page.html",
			expected: "",
		},
		{
			name:     "empty haystack",
			haystack: "",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]any{"path": tc.haystack}
			compiledFilter, err := expr.Compile(
				`LookupFile(path, "test_data_map.json")`,
				GetExprOptions(env)...,
			)
			require.NoError(t, err)

			result, err := expr.Run(compiledFilter, env)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestLookupFileEqualsMatch(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	err = FileInit("testdata", "test_data_map.json", "map")
	require.NoError(t, err)

	tests := []struct {
		name     string
		haystack string
		expected string
	}{
		{
			name:     "exact match on equals entry",
			haystack: "/specific/endpoint.php",
			expected: "SpecificApp",
		},
		{
			name:     "substring of equals entry does NOT match",
			haystack: "/specific/endpoint.php/extra",
			expected: "",
		},
		{
			name:     "prefix of equals entry does NOT match",
			haystack: "/specific/endpoint",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]any{"path": tc.haystack}
			compiledFilter, err := expr.Compile(
				`LookupFile(path, "test_data_map.json")`,
				GetExprOptions(env)...,
			)
			require.NoError(t, err)

			result, err := expr.Run(compiledFilter, env)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestLookupFileEqualsBeforeContains(t *testing.T) {
	// Equals should be checked before contains.
	// To test priority, we verify that an exact equals entry takes precedence
	// over a contains entry with the same pattern.
	err := Init(nil)
	require.NoError(t, err)

	// Set up a custom data file with overlapping equals and contains entries
	dataFileMap = make(map[string]*fileMapEntry)

	entry := &fileMapEntry{
		filename: "overlap_test.json",
		rows: []map[string]string{
			{"pattern": "/overlap/path", "tag": "ContainsTech", "type": "contains"},
			{"pattern": "/overlap/path", "tag": "EqualsTech", "type": "equals"},
		},
	}
	dataFileMap["overlap_test.json"] = entry
	entry.buildIndex()

	env := map[string]any{"path": "/overlap/path"}
	compiledFilter, err := expr.Compile(
		`LookupFile(path, "overlap_test.json")`,
		GetExprOptions(env)...,
	)
	require.NoError(t, err)

	result, err := expr.Run(compiledFilter, env)
	require.NoError(t, err)
	assert.Equal(t, "EqualsTech", result, "equals should take priority over contains")
}

func TestLookupFileRegexMatch(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	err = FileInit("testdata", "test_data_map.json", "map")
	require.NoError(t, err)

	tests := []struct {
		name     string
		haystack string
		expected string
	}{
		{
			name:     "match WordPress plugin readme via regex",
			haystack: "/wp-content/plugins/akismet/readme.txt",
			expected: "WordPress-Plugin",
		},
		{
			name:     "match VPN endpoint via regex",
			haystack: "/dana/somepath",
			expected: "VPN-Endpoint",
		},
		{
			name:     "match VPN logon endpoint via regex",
			haystack: "/logon/LogonPoint/receiver",
			expected: "VPN-Endpoint",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]any{"path": tc.haystack}
			compiledFilter, err := expr.Compile(
				`LookupFile(path, "test_data_map.json")`,
				GetExprOptions(env)...,
			)
			require.NoError(t, err)

			result, err := expr.Run(compiledFilter, env)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestLookupFileContainsBeforeRegex(t *testing.T) {
	// AC (contains) matches should be checked before regex matches.
	// If a URL matches both a contains and a regex pattern, contains wins.
	err := Init(nil)
	require.NoError(t, err)

	err = FileInit("testdata", "test_data_map.json", "map")
	require.NoError(t, err)

	// /wp-admin/ matches the "contains" WordPress entry, even though
	// a regex entry for WordPress-Plugin also exists.
	env := map[string]any{"path": "/wp-admin/plugins/akismet/readme.txt"}
	compiledFilter, err := expr.Compile(
		`LookupFile(path, "test_data_map.json")`,
		GetExprOptions(env)...,
	)
	require.NoError(t, err)

	result, err := expr.Run(compiledFilter, env)
	require.NoError(t, err)
	assert.Equal(t, "WordPress", result, "contains match should take priority over regex")
}

func TestLookupFileMissingFile(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	env := map[string]any{"path": "/tmui/"}
	compiledFilter, err := expr.Compile(
		`LookupFile(path, "nonexistent.json")`,
		GetExprOptions(env)...,
	)
	require.NoError(t, err)

	result, err := expr.Run(compiledFilter, env)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestResetClearsMap(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	err = FileInit("testdata", "test_data_map.json", "map")
	require.NoError(t, err)

	_, ok := dataFileMap["test_data_map.json"]
	require.True(t, ok)

	ResetDataFiles()

	_, ok = dataFileMap["test_data_map.json"]
	assert.False(t, ok, "dataFileMap should be cleared after ResetDataFiles")
}

func TestLookupFileFilterPattern(t *testing.T) {
	// Test the full scenario-like pattern: LookupFile != "" acts as a filter
	err := Init(nil)
	require.NoError(t, err)

	err = FileInit("testdata", "test_data_map.json", "map")
	require.NoError(t, err)

	tests := []struct {
		name     string
		haystack string
		result   bool
	}{
		{
			name:     "matching URL evaluates to true",
			haystack: "/tmui/login.jsp",
			result:   true,
		},
		{
			name:     "non-matching URL evaluates to false",
			haystack: "/normal/page.html",
			result:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]any{"path": tc.haystack}
			compiledFilter, err := expr.Compile(
				`LookupFile(path, "test_data_map.json") != ""`,
				GetExprOptions(env)...,
			)
			require.NoError(t, err)

			result, err := expr.Run(compiledFilter, env)
			require.NoError(t, err)
			assert.Equal(t, tc.result, result)
		})
	}
}

func BenchmarkLookupFile(b *testing.B) {
	err := Init(nil)
	if err != nil {
		b.Fatal(err)
	}

	// Generate a large test data file in memory
	dataFileMap = make(map[string]*fileMapEntry)

	entry := &fileMapEntry{filename: "bench.json"}
	// Add 100 equals entries
	for i := range 100 {
		entry.rows = append(entry.rows, map[string]string{
			"pattern": fmt.Sprintf("/exact-%d", i),
			"tag":     fmt.Sprintf("ExactTech-%d", i),
			"type":    "equals",
		})
	}
	// Add 500 contains entries
	for i := range 500 {
		entry.rows = append(entry.rows, map[string]string{
			"pattern": fmt.Sprintf("/probe-%d/", i),
			"tag":     fmt.Sprintf("Tech-%d", i),
			"type":    "contains",
		})
	}
	// Add 50 regex entries
	for i := range 50 {
		entry.rows = append(entry.rows, map[string]string{
			"pattern": fmt.Sprintf("/regex-%d/[a-z]+", i),
			"tag":     fmt.Sprintf("RegexTech-%d", i),
			"type":    "regex",
		})
	}

	dataFileMap["bench.json"] = entry
	entry.buildIndex()

	b.Run("equals_match", func(b *testing.B) {
		for range b.N {
			result, _ := LookupFile("/exact-50", "bench.json")
			if result != "ExactTech-50" {
				b.Fatalf("unexpected result: %s", result)
			}
		}
	})

	b.Run("contains_match", func(b *testing.B) {
		haystack := "/some/path/probe-499/admin"
		for range b.N {
			result, _ := LookupFile(haystack, "bench.json")
			if result != "Tech-499" {
				b.Fatalf("unexpected result: %s", result)
			}
		}
	})

	b.Run("regex_match", func(b *testing.B) {
		haystack := "/regex-49/abcdef"
		for range b.N {
			result, _ := LookupFile(haystack, "bench.json")
			if result != "RegexTech-49" {
				b.Fatalf("unexpected result: %s", result)
			}
		}
	})

	b.Run("no_match", func(b *testing.B) {
		haystack := "/completely/normal/path/nothing/matches/here"
		for range b.N {
			result, _ := LookupFile(haystack, "bench.json")
			if result != "" {
				b.Fatalf("unexpected result: %s", result)
			}
		}
	})
}
