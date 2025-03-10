package ja4h

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
)

// see: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.png
// [JA4H_a]_[JA4H_b]_[JA4H_c]_[JA4H_d]

// JA4H_a:
// [httpMethod] [httpVersion] [hasCookie] [hasReferer] [countHeaders] [primaryLanguage]
//  2         2         1         1            2              4               12

// JA4H_b: [headers hash]

// JA4H_c: [cookie name hash]

const (
	truncatedHashLength = 12
	ja4hFullHashLength  = 51
	ja4hSubHashLength   = 12
	defaultLang         = "0000"
	emptyCookiesHash    = "000000000000"
)

// httpMethod extracts the first two lowercase characters of the HTTP method.
func httpMethod(method string) string {
	l := min(len(method), 2)
	return strings.ToLower(method[:l])
}

// httpVersion extracts the version number from the HTTP protocol.
// The version is truncated to one digit each, but I believe the  http server will control this anyway.
func httpVersion(major int, minor int) string {
	return fmt.Sprintf("%d%d", major%10, minor%10)
}

// hasCookie checks if the request has any cookies.
func hasCookie(req *http.Request) string {
	if len(req.Cookies()) > 0 {
		return "c"
	}
	return "n"
}

// hasReferer checks if the Referer header is set.
func hasReferer(referer string) string {
	if referer != "" {
		return "r"
	}
	return "n"
}

// countHeaders counts the headers, excluding specific ones like Cookie and Referer.
func countHeaders(headers http.Header) string {
	count := len(headers)
	if headers.Get("Cookie") != "" {
		count--
	}
	if headers.Get("Referer") != "" {
		count--
	}
	//header len needs to be on 2 chars: 3 -> 03 // 100 -> 99
	return fmt.Sprintf("%02d", min(count, 99))
}

// primaryLanguage extracts the first four characters of the primary Accept-Language header.
func primaryLanguage(headers http.Header) string {
	lang := strings.ToLower(headers.Get("Accept-Language"))
	if lang == "" {
		return defaultLang
	}
	//cf. https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4h.py#L13
	lang = strings.ReplaceAll(lang, "-", "")
	lang = strings.ReplaceAll(lang, ";", ",")

	value := strings.Split(lang, ",")[0]
	value = value[:min(len(value), 4)]
	return value + strings.Repeat("0", 4-len(value))
}

// jA4H_a generates a summary fingerprint for the HTTP request.
func jA4H_a(req *http.Request) string {
	var builder strings.Builder

	builder.Grow(ja4hSubHashLength)
	builder.WriteString(httpMethod(req.Method))
	builder.WriteString(httpVersion(req.ProtoMajor, req.ProtoMinor))
	builder.WriteString(hasCookie(req))
	builder.WriteString(hasReferer(req.Referer()))
	builder.WriteString(countHeaders(req.Header))
	builder.WriteString(primaryLanguage(req.Header))
	return builder.String()
}

// jA4H_b computes a truncated SHA256 hash of sorted header names.
func jA4H_b(req *http.Request) string {

	// The reference implementation (https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4h.py#L27)
	// discards referer and headers **starting with "cookie"**
	// If there's no headers, it hashes the empty string, instead of returning 0s
	// like what is done for cookies. Not sure if it's intended or an oversight in the spec.
	headers := make([]string, 0, len(req.Header))
	for name := range req.Header {
		if strings.HasPrefix(strings.ToLower(name), "cookie") || strings.ToLower(name) == "referer" {
			continue
		}
		headers = append(headers, name)
	}
	sort.Strings(headers)

	return hashTruncated(strings.Join(headers, ","))
}

// hashTruncated computes a truncated SHA256 hash for the given input.
func hashTruncated(input string) string {
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", hash)[:truncatedHashLength]
}

// jA4H_c computes a truncated SHA256 hash of sorted cookie names.
func jA4H_c(cookies []*http.Cookie) string {
	if len(cookies) == 0 {
		return emptyCookiesHash
	}
	var builder strings.Builder
	for i, cookie := range cookies {
		builder.WriteString(cookie.Name)
		if i < len(cookies)-1 {
			builder.WriteString(",")
		}
	}
	return hashTruncated(builder.String())
}

// jA4H_d computes a truncated SHA256 hash of cookie name-value pairs.
func jA4H_d(cookies []*http.Cookie) string {
	if len(cookies) == 0 {
		return emptyCookiesHash
	}
	var builder strings.Builder
	for i, cookie := range cookies {
		builder.WriteString(cookie.Name)
		builder.WriteString("=")
		builder.WriteString(cookie.Value)
		if i < len(cookies)-1 {
			builder.WriteString(",")
		}
	}
	return hashTruncated(builder.String())
}

// JA4H computes the complete HTTP client fingerprint based on the request.
func JA4H(req *http.Request) string {
	JA4H_a := jA4H_a(req)
	JA4H_b := jA4H_b(req)

	cookies := req.Cookies()

	slices.SortFunc(cookies, func(a, b *http.Cookie) int {
		return strings.Compare(a.Name, b.Name)
	})

	JA4H_c := jA4H_c(cookies)
	JA4H_d := jA4H_d(cookies)

	var builder strings.Builder

	//JA4H is a fixed size, allocated it all at once
	builder.Grow(ja4hFullHashLength)
	builder.WriteString(JA4H_a)
	builder.WriteString("_")
	builder.WriteString(JA4H_b)
	builder.WriteString("_")
	builder.WriteString(JA4H_c)
	builder.WriteString("_")
	builder.WriteString(JA4H_d)

	return builder.String()
}
