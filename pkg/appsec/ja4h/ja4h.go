package ja4h

import (
	"crypto/sha256"
	"fmt"
	"net/http"
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

const truncatedHashLength = 12
const defaultLang = "0000"

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

	return strings.Split(lang, ",")[0] + strings.Repeat("0", 4-len(lang))
}

// jA4H_a generates a summary fingerprint for the HTTP request.
func jA4H_a(req *http.Request) string {
	return fmt.Sprintf("%s%s%s%s%s%s",
		httpMethod(req.Method),
		httpVersion(req.ProtoMajor, req.ProtoMinor),
		hasCookie(req),
		hasReferer(req.Referer()),
		countHeaders(req.Header),
		primaryLanguage(req.Header),
	)
}

// jA4H_b computes a truncated SHA256 hash of sorted header names.
func jA4H_b(req *http.Request) string {

	// The reference implementation (https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4h.py#L27)
	// discards referer and headers **starting with "cookie"**
	headers := make([]string, 0, len(req.Header))
	for name := range req.Header {
		if strings.HasPrefix(strings.ToLower(name), "cookie") || strings.ToLower(name) == "referer" {
			continue
		}
		headers = append(headers, name)
	}
	sort.Strings(headers)

	return hashTruncated(strings.Join(headers, ""))
}

// hashTruncated computes a truncated SHA256 hash for the given input.
func hashTruncated(input string) string {
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", hash)[:truncatedHashLength]
}

// jA4H_c computes a truncated SHA256 hash of sorted cookie names.
func jA4H_c(orderedCookies []string) string {
	if len(orderedCookies) == 0 {
		return strings.Repeat("0", truncatedHashLength)
	}
	return hashTruncated(strings.Join(orderedCookies, ","))
}

// jA4H_d computes a truncated SHA256 hash of cookie name-value pairs.
func jA4H_d(orderedCookies []string, cookieMap map[string]string) string {
	if len(orderedCookies) == 0 {
		return strings.Repeat("0", truncatedHashLength)
	}
	var builder strings.Builder
	for _, name := range orderedCookies {
		builder.WriteString(name)
		builder.WriteString("=")
		builder.WriteString(cookieMap[name])
	}
	return hashTruncated(builder.String())
}

// JA4H computes the complete HTTP client fingerprint based on the request.
func JA4H(req *http.Request) string {
	JA4H_a := jA4H_a(req)
	JA4H_b := jA4H_b(req)

	cookieMap := make(map[string]string)
	var orderedCookies []string
	for _, c := range req.Cookies() {
		cookieMap[c.Name] = c.Value
		orderedCookies = append(orderedCookies, c.Name)
	}
	sort.Strings(orderedCookies)

	JA4H_c := jA4H_c(orderedCookies)
	JA4H_d := jA4H_d(orderedCookies, cookieMap)

	return fmt.Sprintf("%s_%s_%s_%s", JA4H_a, JA4H_b, JA4H_c, JA4H_d)
}
