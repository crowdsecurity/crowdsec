package appsec

import (
	"net/http"
	"strings"
	"time"
)

const (
	defaultCookiePath     = "/"
	defaultCookieSameSite = "Lax"
)

type AppsecCookie struct {
	Name         string
	Expiration   int64
	Val          string
	PathVal      string
	DomainName   string
	SecureFlag   bool
	HttpOnlyFlag bool
	SameSiteMode string
}

// NewAppsecCookie returns a cookie pre-populated with sensible defaults.
// Defaults: Path "/", SameSite=Lax, session lifetime, not secure/httponly unless set.
func NewAppsecCookie(name string) *AppsecCookie {
	return (&AppsecCookie{Name: name}).withDefaults()
}

// Cookie is a short alias for NewAppsecCookie.
func Cookie(name string) *AppsecCookie {
	return NewAppsecCookie(name)
}

func (c *AppsecCookie) withDefaults() *AppsecCookie {
	if c.PathVal == "" {
		c.PathVal = defaultCookiePath
	}

	if c.SameSiteMode == "" {
		c.SameSiteMode = defaultCookieSameSite
	}

	return c
}

func (c *AppsecCookie) Value(value string) *AppsecCookie {
	c.Val = value
	return c
}

func (c *AppsecCookie) Path(path string) *AppsecCookie {
	if path == "" {
		path = defaultCookiePath
	}

	c.PathVal = path
	return c
}

func (c *AppsecCookie) Domain(domain string) *AppsecCookie {
	c.DomainName = domain
	return c
}

func (c *AppsecCookie) Secure() *AppsecCookie {
	c.SecureFlag = true
	return c
}

func (c *AppsecCookie) HttpOnly() *AppsecCookie {
	c.HttpOnlyFlag = true
	return c
}

func (c *AppsecCookie) SameSite(mode string) *AppsecCookie {
	c.SameSiteMode = mode
	return c
}

// ExpiresAt sets an absolute expiration time (unix seconds).
func (c *AppsecCookie) ExpiresAt(t time.Time) *AppsecCookie {
	c.Expiration = t.Unix()
	return c
}

// ExpiresIn sets the expiration relative to now.
func (c *AppsecCookie) ExpiresIn(d time.Duration) *AppsecCookie {
	c.Expiration = time.Now().Add(d).Unix()
	return c
}

// String formats the cookie into a Set-Cookie compatible string.
func (c *AppsecCookie) String() string {
	c.withDefaults()

	cookie := http.Cookie{
		Name:     c.Name,
		Value:    c.Val,
		Path:     c.PathVal,
		Domain:   c.DomainName,
		Secure:   c.SecureFlag,
		HttpOnly: c.HttpOnlyFlag,
		SameSite: toSameSite(c.SameSiteMode),
	}

	if c.Expiration > 0 {
		cookie.Expires = time.Unix(c.Expiration, 0).UTC()
		cookie.MaxAge = int(time.Until(cookie.Expires).Seconds())
	}

	// SameSite=None requires Secure=true per modern browsers; enforce to avoid invalid cookies.
	if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
		cookie.Secure = true
	}

	return cookie.String()
}

func toSameSite(mode string) http.SameSite {
	switch strings.ToLower(mode) {
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}
