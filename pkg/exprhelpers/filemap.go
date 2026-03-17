package exprhelpers

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sync"

	aho_corasick "github.com/petar-dambovaliev/aho-corasick"
	log "github.com/sirupsen/logrus"
)

// dataFileMap holds pre-parsed JSON-lines map data, keyed by filename.
var dataFileMap map[string]*fileMapEntry

// validMapEntryTypes lists the recognized values for the mandatory "type" field in map data files.
var validMapEntryTypes = map[string]bool{
	"equals":   true,
	"contains": true,
	"regex":    true,
}

// fileMapEntry holds the parsed JSON-lines data and a lazily-built match index.
// The pattern field is always "pattern" and the value field is always "tag".
type fileMapEntry struct {
	rows  []map[string]string
	mu    sync.Mutex
	index *matchIndex // lazily built, always uses "pattern" field
}

// matchIndex holds the pre-built matching structures for a given pattern field.
type matchIndex struct {
	// O(1) map for "equals" entries (checked first).
	equalsMap map[string]int // exact pattern value → row index

	// Aho-Corasick automaton for "contains" entries (O(|haystack|) matching, checked second).
	acAutomaton    *aho_corasick.AhoCorasick
	acPatternToRow []int // AC pattern index → row index in fileMapEntry.rows

	// Pre-compiled regexps for "regex" entries (checked last).
	regexPatterns []*regexp.Regexp
	regexToRow    []int // regex slice index → row index in fileMapEntry.rows
}

// fileMapInit parses a single JSON line and appends it to the fileMapEntry for the given filename.
// Three fields are mandatory: "pattern", "tag", and "type" (one of: "equals", "contains", "regex").
func fileMapInit(filename string, line string) error {
	var record map[string]string
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		return fmt.Errorf("failed to parse JSON line in %s: %w", filename, err)
	}

	if record["pattern"] == "" {
		return fmt.Errorf("missing mandatory 'pattern' field in %s: %s", filename, line)
	}

	if record["tag"] == "" {
		return fmt.Errorf("missing mandatory 'tag' field in %s: %s", filename, line)
	}

	entryType := record["type"]
	if entryType == "" {
		return fmt.Errorf("missing mandatory 'type' field in %s: %s", filename, line)
	}

	if !validMapEntryTypes[entryType] {
		return fmt.Errorf("unknown entry type '%s' in %s: %s", entryType, filename, line)
	}

	if entryType == "regex" {
		if _, err := regexp.Compile(record["pattern"]); err != nil {
			log.Warningf("invalid regex pattern in %s: %s", filename, err)
		}
	}

	if dataFileMap[filename] == nil {
		dataFileMap[filename] = &fileMapEntry{}
	}

	dataFileMap[filename].rows = append(dataFileMap[filename].rows, record)

	return nil
}

// getOrBuildIndex returns the cached matchIndex, building it on first access.
// It always indexes on the "pattern" field. Rows are partitioned by their "type" field
// (validated at load time):
//   - "equals"   → inserted into equalsMap for O(1) lookup
//   - "contains" → fed to Aho-Corasick automaton builder
//   - "regex"    → compiled to *regexp.Regexp
func (e *fileMapEntry) getOrBuildIndex() *matchIndex {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.index != nil {
		return e.index
	}

	idx := &matchIndex{
		equalsMap: make(map[string]int),
	}

	var acPatterns []string

	for i, row := range e.rows {
		val := row["pattern"]

		switch row["type"] {
		case "equals":
			if prev, exists := idx.equalsMap[val]; exists {
				log.Warningf("fileMapEntry: duplicate equals pattern '%s' (row %d overrides row %d)", val, i, prev)
			}

			idx.equalsMap[val] = i
		case "regex":
			re, err := regexp.Compile(val)
			if err != nil {
				log.Errorf("fileMapEntry: invalid regex pattern '%s' in row %d: %s", val, i, err)
				continue
			}

			idx.regexPatterns = append(idx.regexPatterns, re)
			idx.regexToRow = append(idx.regexToRow, i)
		case "contains":
			acPatterns = append(acPatterns, val)
			idx.acPatternToRow = append(idx.acPatternToRow, i)
		default:
			continue
		}
	}

	if len(acPatterns) > 0 {
		builder := aho_corasick.NewAhoCorasickBuilder(aho_corasick.Opts{
			AsciiCaseInsensitive: false,
			MatchOnlyWholeWords:  false,
			MatchKind:            aho_corasick.LeftMostFirstMatch,
			DFA:                  true,
		})

		ac := builder.Build(acPatterns)
		idx.acAutomaton = &ac
	}

	e.index = idx

	return idx
}

// FileMap returns the pre-parsed JSON-lines data for the given filename.
// Each element is a map[string]string representing one JSON line.
// func FileMap(filename string) []map[string]string
func FileMap(params ...any) (any, error) {
	filename := params[0].(string)

	entry, ok := dataFileMap[filename]
	if !ok {
		log.Errorf("file '%s' (type:map) not found in expr library", filename)
		return []map[string]string{}, nil
	}

	return entry.rows, nil
}

// LookupFile searches for the first entry in the map file whose "pattern" value
// matches the haystack. Matching is done in priority order:
//  1. "equals" entries via O(1) hash map lookup
//  2. "contains" entries via Aho-Corasick substring matching
//  3. "regex" entries via pre-compiled regexp
//
// Returns the corresponding "tag" value, or "" if no match.
// func LookupFile(haystack string, filename string) string
func LookupFile(params ...any) (any, error) {
	haystack := params[0].(string)
	filename := params[1].(string)

	entry, ok := dataFileMap[filename]
	if !ok {
		log.Errorf("file '%s' (type:map) not found in expr library", filename)
		return "", nil
	}

	idx := entry.getOrBuildIndex()
	if idx == nil {
		return "", nil
	}

	// Phase 1: Equals map (O(1) exact match)
	if rowIdx, ok := idx.equalsMap[haystack]; ok {
		return entry.rows[rowIdx]["tag"], nil
	}

	// Phase 2: Aho-Corasick for "contains" entries
	if idx.acAutomaton != nil {
		iter := idx.acAutomaton.Iter(haystack)
		if match := iter.Next(); match != nil {
			rowIdx := idx.acPatternToRow[match.Pattern()]

			return entry.rows[rowIdx]["tag"], nil
		}
	}

	// Phase 3: Regex fallback
	for i, re := range idx.regexPatterns {
		if re.MatchString(haystack) {
			rowIdx := idx.regexToRow[i]

			return entry.rows[rowIdx]["tag"], nil
		}
	}

	return "", nil
}
