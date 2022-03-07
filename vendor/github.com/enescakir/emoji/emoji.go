package emoji

import (
	"fmt"
	"strings"
)

// Base attributes
const (
	TonePlaceholder = "@"
	flagBaseIndex   = '\U0001F1E6' - 'a'
)

// Skin tone colors
const (
	Default     Tone = ""
	Light       Tone = "\U0001F3FB"
	MediumLight Tone = "\U0001F3FC"
	Medium      Tone = "\U0001F3FD"
	MediumDark  Tone = "\U0001F3FE"
	Dark        Tone = "\U0001F3FF"
)

// Emoji defines an emoji object with no skin variations.
type Emoji string

// String returns string representation of the simple emoji.
func (e Emoji) String() string {
	return string(e)
}

// EmojiWithTone defines an emoji object that has skin tone options.
type EmojiWithTone struct {
	oneTonedCode string
	twoTonedCode string
	defaultTone  Tone
}

// newEmojiWithTone constructs a new emoji object that has skin tone options.
func newEmojiWithTone(codes ...string) EmojiWithTone {
	if len(codes) == 0 {
		return EmojiWithTone{}
	}

	one := codes[0]
	two := codes[0]

	if len(codes) > 1 {
		two = codes[1]
	}

	return EmojiWithTone{
		oneTonedCode: one,
		twoTonedCode: two,
	}
}

// withDefaultTone sets default tone for an emoji and returns it.
func (e EmojiWithTone) withDefaultTone(tone string) EmojiWithTone {
	e.defaultTone = Tone(tone)

	return e
}

// String returns string representation of the emoji with default skin tone.
func (e EmojiWithTone) String() string {
	return strings.ReplaceAll(e.oneTonedCode, TonePlaceholder, e.defaultTone.String())
}

// Tone returns string representation of the emoji with given skin tone.
func (e EmojiWithTone) Tone(tones ...Tone) string {
	// if no tone given, return with default skin tone
	if len(tones) == 0 {
		return e.String()
	}

	str := e.twoTonedCode
	replaceCount := 1

	// if one tone given or emoji doesn't have twoTonedCode, use oneTonedCode
	// Also, replace all with one tone
	if len(tones) == 1 {
		str = e.oneTonedCode
		replaceCount = -1
	}

	// replace tone one by one
	for _, t := range tones {
		// use emoji's default tone
		if t == Default {
			t = e.defaultTone
		}

		str = strings.Replace(str, TonePlaceholder, t.String(), replaceCount)
	}

	return str
}

// Tone defines skin tone options for emojis.
type Tone string

// String returns string representation of the skin tone.
func (t Tone) String() string {
	return string(t)
}

// CountryFlag returns a country flag emoji from given country code.
// Full list of country codes: https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2
func CountryFlag(code string) (Emoji, error) {
	if len(code) != 2 {
		return "", fmt.Errorf("not valid country code: %q", code)
	}

	code = strings.ToLower(code)
	flag := countryCodeLetter(code[0]) + countryCodeLetter(code[1])

	return Emoji(flag), nil
}

// countryCodeLetter shifts given letter byte as flagBaseIndex.
func countryCodeLetter(l byte) string {
	return string(rune(l) + flagBaseIndex)
}
