package exprhelpers

import (
	"regexp"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

// regexCache stores compiled regex patterns for reuse
type regexCache struct {
	mu    sync.RWMutex
	cache map[string]*regexp.Regexp
}

var (
	regexCacheInstance = &regexCache{
		cache: make(map[string]*regexp.Regexp),
	}
)

// getCompiledRegex returns a compiled regex pattern from cache or compiles and caches it
func (rc *regexCache) getCompiledRegex(pattern string) (*regexp.Regexp, error) {
	// Try to get from cache first (read lock)
	rc.mu.RLock()
	if re, exists := rc.cache[pattern]; exists {
		rc.mu.RUnlock()
		return re, nil
	}
	rc.mu.RUnlock()

	// Compile the regex (write lock)
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Double-check after acquiring write lock
	if re, exists := rc.cache[pattern]; exists {
		return re, nil
	}

	// Compile and cache
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	rc.cache[pattern] = re
	return re, nil
}

//Wrappers for stdlib strings function exposed in expr

func Fields(params ...any) (any, error) {
	return strings.Fields(params[0].(string)), nil
}

func Index(params ...any) (any, error) {
	return strings.Index(params[0].(string), params[1].(string)), nil
}

func IndexAny(params ...any) (any, error) {
	return strings.IndexAny(params[0].(string), params[1].(string)), nil
}

func Join(params ...any) (any, error) {
	return strings.Join(params[0].([]string), params[1].(string)), nil
}

func Split(params ...any) (any, error) {
	return strings.Split(params[0].(string), params[1].(string)), nil
}

func SplitAfter(params ...any) (any, error) {
	return strings.SplitAfter(params[0].(string), params[1].(string)), nil
}

func SplitAfterN(params ...any) (any, error) {
	return strings.SplitAfterN(params[0].(string), params[1].(string), params[2].(int)), nil
}

func SplitN(params ...any) (any, error) {
	return strings.SplitN(params[0].(string), params[1].(string), params[2].(int)), nil
}

func Replace(params ...any) (any, error) {
	return strings.Replace(params[0].(string), params[1].(string), params[2].(string), params[3].(int)), nil
}

func ReplaceAll(params ...any) (any, error) {
	return strings.ReplaceAll(params[0].(string), params[1].(string), params[2].(string)), nil
}

func ReplaceRegexp(params ...any) (any, error) {
	re, err := regexCacheInstance.getCompiledRegex(params[0].(string))
	if err != nil {
		return nil, err
	}
	// Replace only the first occurrence
	loc := re.FindStringIndex(params[1].(string))
	if loc == nil {
		return params[1].(string), nil // No match found, return original string
	}
	start, end := loc[0], loc[1]
	return params[1].(string)[:start] + params[2].(string) + params[1].(string)[end:], nil
}

func ReplaceAllRegex(params ...any) (any, error) {
	re, err := regexCacheInstance.getCompiledRegex(params[0].(string))
	if err != nil {
		return nil, err
	}
	return re.ReplaceAllString(params[1].(string), params[2].(string)), nil
}

func Trim(params ...any) (any, error) {
	return strings.Trim(params[0].(string), params[1].(string)), nil
}

func TrimLeft(params ...any) (any, error) {
	return strings.TrimLeft(params[0].(string), params[1].(string)), nil
}

func TrimPrefix(params ...any) (any, error) {
	return strings.TrimPrefix(params[0].(string), params[1].(string)), nil
}

func TrimRight(params ...any) (any, error) {
	return strings.TrimRight(params[0].(string), params[1].(string)), nil
}

func TrimSpace(params ...any) (any, error) {
	return strings.TrimSpace(params[0].(string)), nil
}

func TrimSuffix(params ...any) (any, error) {
	return strings.TrimSuffix(params[0].(string), params[1].(string)), nil
}

func LogInfo(params ...any) (any, error) {
	log.Infof(params[0].(string), params[1:]...)
	return true, nil
}

func AnsiRegex(params ...any) (any, error) {
	// Returns the regex pattern for ANSI escape sequences
	// This can be used with ReplaceRegexp() or ReplaceAllRegex() functions
	// Matches \x1b (hex) and \033 (octal) representations
	return `\x1b\[[0-9;]*m|\033\[[0-9;]*m`, nil
}
