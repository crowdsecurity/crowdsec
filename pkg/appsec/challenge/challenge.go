package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"text/template"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/cookie"
	log "github.com/sirupsen/logrus"
)

const ChallengeJSPath = "/crowdsec-internal/challenge/challenge.js"
const ChallengeSubmitPath = "/crowdsec-internal/challenge/submit"
const ChallengeCookieName = "__crowdsec_challenge"

// FIXME
const masterSecret = "SUPER_SECRET_KEY"

//go:embed js/src/*
var jsFS embed.FS

//go:embed challenge.html.tmpl
var htmlTemplate string

//go:embed challenge.js
var jsChallenge string

func getTicket(userAgent string, ts string) (string, string) {
	if ts == "" {
		ts = strconv.FormatInt(time.Now().UnixNano(), 10)
	}

	h := hmac.New(sha256.New, []byte(masterSecret))

	// TODO: what should we do if UA is empty ?
	ua_hash := sha256.Sum256([]byte(userAgent))
	h.Write(ua_hash[:])
	h.Write([]byte(ts))

	return fmt.Sprintf("%x", h.Sum(nil)), ts
}

func GetChallengePage(userAgent string) (string, error) {
	// We are using text/template instead of html/template because the data we send is pretty much hardcoded and trusted.
	// Using html/template would escape the JS code we are adding, making it unusable.
	templateObj, err := template.New("challenge").Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse challenge template: %w", err)
	}

	jsTemplateObj, err := template.New("challengeJS").Parse(jsChallenge)
	if err != nil {
		return "", fmt.Errorf("failed to parse challenge JS template: %w", err)
	}

	var jsChallengeBuilder strings.Builder

	ticket, now := getTicket(userAgent, "")

	err = jsTemplateObj.Execute(&jsChallengeBuilder, map[string]string{
		"Ticket":    ticket,
		"Timestamp": now,
	})

	if err != nil {
		return "", fmt.Errorf("failed to execute challenge JS template: %w", err)
	}

	var renderedPage strings.Builder

	templateObj.Execute(&renderedPage, map[string]string{
		"JSChallenge": jsChallengeBuilder.String(),
	})
	return renderedPage.String(), nil
}

func getSessionKey(ticket string) string {
	hash := sha256.Sum256([]byte(ticket))
	return fmt.Sprintf("%x", hash)
}

func decryptFingerprint(sessionKey string, encrypted string) (string, error) {
	// Decode the base64-encoded encrypted fingerprint
	encryptedBytes, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted fingerprint: %w", err)
	}

	decryptedBytes := make([]byte, len(encryptedBytes))

	for i := range encryptedBytes {
		decryptedBytes[i] = encryptedBytes[i] ^ sessionKey[i%len(sessionKey)]
	}

	decrypted := string(decryptedBytes)
	return decrypted, nil
}

func ValidateChallengeResponse(request *http.Request, body []byte) (*cookie.AppsecCookie, FingerprintData, error) {
	vars, err := url.ParseQuery(string(body))

	if err != nil {
		return nil, FingerprintData{}, fmt.Errorf("failed to parse challenge response: %w", err)
	}

	encryptedFingerprint := vars.Get("f")
	clientTicket := vars.Get("t")
	clientTS := vars.Get("ts")
	clientHMAC := vars.Get("h")
	clientSessionKey := vars.Get("s")
	userAgent := request.UserAgent()

	if encryptedFingerprint == "" || clientTicket == "" || clientTS == "" || clientHMAC == "" || clientSessionKey == "" {
		return nil, FingerprintData{}, fmt.Errorf("missing required fields in challenge response")
	}

	tsInt, err := strconv.ParseInt(clientTS, 10, 64)
	if err != nil {
		return nil, FingerprintData{}, fmt.Errorf("invalid timestamp in challenge response: %w", err)
	}

	// Quickly reject if the timestamp is too old: even if it's forged, it's still too old. Don't bother doing HMAC if the response is already expired.
	if time.Since(time.Unix(0, tsInt)) > 2*time.Minute {
		return nil, FingerprintData{}, fmt.Errorf("challenge response expired")
	}

	// Recompute the ticket so that we can validate the one sent by the client
	ticketKey, _ := getTicket(userAgent, clientTS)

	sessionKey := getSessionKey(ticketKey)

	// If the key sent by the client is different from the one we just derived, something is wrong, drop the request.
	if sessionKey != clientSessionKey {
		log.Infof("Expected session key: %s | client session key: %s", sessionKey, clientSessionKey)
		return nil, FingerprintData{}, fmt.Errorf("invalid session key in challenge response")
	}

	// Now recompute the HMAC from encrypted fingerprint + timestamp + ticket

	expectedHMAC := hmac.New(sha256.New, []byte(sessionKey))

	expectedHMAC.Write([]byte(encryptedFingerprint))
	expectedHMAC.Write([]byte(clientTS))
	expectedHMAC.Write([]byte(ticketKey))

	expectedHMACB := fmt.Sprintf("%x", expectedHMAC.Sum(nil))

	if !hmac.Equal([]byte(clientHMAC), []byte(expectedHMACB)) {
		log.Infof("Expected HMAC: %s | Received HMAC: %s", expectedHMACB, clientHMAC)
		return nil, FingerprintData{}, fmt.Errorf("invalid HMAC in challenge response")
	}

	fingerprint, err := decryptFingerprint(sessionKey, encryptedFingerprint)
	if err != nil {
		return nil, FingerprintData{}, fmt.Errorf("failed to decrypt fingerprint: %w", err)
	}

	var fpData FingerprintData

	err = json.Unmarshal([]byte(fingerprint), &fpData)

	if err != nil {
		return nil, FingerprintData{}, fmt.Errorf("failed to unmarshal fingerprint data: %w", err)
	}

	// FIXME: make this configurable
	//now := time.Now()

	// Would JWE be better and simpler here ?
	cookieHMAC := hmac.New(sha256.New, []byte(masterSecret))
	cookieHMAC.Write([]byte(userAgent))

	// Initial plan was to use expiration time as part of the HMAC
	// But it would also be part of the cookie, and the expiration time by itself is not sent by the client
	// So this means that we would need to partially trust some data from the cookie before validating it (and it would be used to derive the HMAC key), which seems bad.

	// Cookie value is encrypted value of {"iat": now, "f": fingerprint}
	// HMAC is computed with expiration time + user agent, so that the cookie is tied to both the client and a specific time window.

	cookieValue := fmt.Sprintf("%x", cookieHMAC.Sum(nil))

	c := cookie.NewAppsecCookie(ChallengeCookieName).HttpOnly().Path("/").SameSite(cookie.SameSiteLax).ExpiresIn(2 * time.Hour).Value(cookieValue)
	if request.URL.Scheme == "https" {
		c = c.Secure()
	}
	return c, fpData, nil
}

func ValidCookie(cookie *http.Cookie) bool {
	if cookie == nil {
		return false
	}
	return true
}
