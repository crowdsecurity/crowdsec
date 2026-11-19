package challenge

import (
	"fmt"
	"html"
	"regexp"
	"strings"
)

// DefaultPageTitle is the challenge page title when no hook sets one.
const DefaultPageTitle = "CrowdSec Challenge"

// Caps on what hooks can put in the page. They come from request-time expr,
// so a bad rule mustn't be able to make every challenge page arbitrarily big.
const (
	maxPageTitleLen = 256
	maxPageMetaTags = 32
	maxPageVars     = 32
	maxPageValueLen = 2048
)

var (
	// Lowercase only: og:/twitter: properties are case-sensitive and defined lowercase.
	metaKeyRe = regexp.MustCompile(`^(description|(og|twitter):[a-z0-9_:.-]+)$`)
	// Must be usable as {{.Vars.name}} in a template.
	pageVarRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

type metaTag struct {
	key   string
	value string
}

// PageOverrides is the per-request customization of the challenge page, set
// by expr hooks. The zero value renders the default page.
type PageOverrides struct {
	title string
	meta  []metaTag
	vars  map[string]string
}

func (p *PageOverrides) SetTitle(title string) error {
	if len(title) > maxPageTitleLen {
		return fmt.Errorf("challenge page title is %d bytes, max %d", len(title), maxPageTitleLen)
	}

	p.title = title

	return nil
}

// SetMeta adds a <meta> tag, or replaces the value of one already set with
// the same key. Only description, og:* and twitter:* are allowed.
func (p *PageOverrides) SetMeta(key, value string) error {
	if !metaKeyRe.MatchString(key) {
		return fmt.Errorf("challenge page meta %q: only description, og:* and twitter:* are allowed", key)
	}

	if len(value) > maxPageValueLen {
		return fmt.Errorf("challenge page meta %q is %d bytes, max %d", key, len(value), maxPageValueLen)
	}

	for i := range p.meta {
		if p.meta[i].key == key {
			p.meta[i].value = value
			return nil
		}
	}

	if len(p.meta) >= maxPageMetaTags {
		return fmt.Errorf("challenge page already has %d meta tags", maxPageMetaTags)
	}

	p.meta = append(p.meta, metaTag{key: key, value: value})

	return nil
}

// SetVar sets a value a custom page reads as {{.Vars.name}}. The built-in
// page doesn't use any.
func (p *PageOverrides) SetVar(name, value string) error {
	if !pageVarRe.MatchString(name) {
		return fmt.Errorf("challenge page var %q: must be a letter or underscore followed by letters, digits or underscores", name)
	}

	if len(value) > maxPageValueLen {
		return fmt.Errorf("challenge page var %q is %d bytes, max %d", name, len(value), maxPageValueLen)
	}

	if _, ok := p.vars[name]; !ok && len(p.vars) >= maxPageVars {
		return fmt.Errorf("challenge page already has %d vars", maxPageVars)
	}

	if p.vars == nil {
		p.vars = make(map[string]string)
	}

	p.vars[name] = value

	return nil
}

// addTo puts the overrides in the template data. Everything is HTML-escaped
// here because the page is rendered with text/template, which escapes nothing.
func (p *PageOverrides) addTo(data map[string]interface{}) {
	title := DefaultPageTitle
	if p.title != "" {
		title = p.title
	}

	data["Title"] = html.EscapeString(title)

	var meta strings.Builder

	for _, m := range p.meta {
		// Open Graph is specified with property=, everything else with name=.
		attr := "name"
		if strings.HasPrefix(m.key, "og:") {
			attr = "property"
		}

		fmt.Fprintf(&meta, "<meta %s=\"%s\" content=\"%s\" />\n", attr, m.key, html.EscapeString(m.value))
	}

	data["Meta"] = meta.String()

	vars := make(map[string]string, len(p.vars))
	for k, v := range p.vars {
		vars[k] = html.EscapeString(v)
	}

	data["Vars"] = vars
}
