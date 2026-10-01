package appsec

import (
	"slices"
	"strconv"
	"strings"
)

// Floor for a blank name reaching Add() from Go. The expr helper rejects one
// outright; this only has to keep a detection from being nameless on either
// axis, since the category defaults to the name.
const unspecifiedScoreReason = "unspecified"

// Authoritative for scoring. Insertion-ordered.
type categoryScore struct {
	category string
	score    int
	// Set by Set(). Without it, a category scoring 10 next to detections
	// totalling 62 reads as a bug instead of a deliberate override.
	override bool
}

// Append-only record of what fired. A reset rewrites the category score, never
// this, so an alert can always say which signals triggered.
type detection struct {
	name     string
	category string
	score    int
}

// How a detection appears in the breakdown. A signal that named no category is
// its own category, so the prefix would just repeat the name: dropping it is
// also what every pre-category config already emits.
func (d detection) key() string {
	if d.category == d.name {
		return d.name
	}

	return d.category + ":" + d.name
}

// RequestScore accumulates per-request suspicion points. The category scores are
// what the request is worth; the detections are the record of what fired. They
// are deliberately separate, because a reset changes the former and not the
// latter — so the two deliberately disagree once Set() has been used.
//
// Every detection has a category: one that names none is filed under its own
// name. The request score is therefore the sum of the category scores.
type RequestScore struct {
	categories []categoryScore
	detections []detection
}

func (s *RequestScore) categoryIndex(category string) int {
	return slices.IndexFunc(s.categories, func(c categoryScore) bool {
		return c.category == category
	})
}

func (s *RequestScore) addToCategory(category string, points int) {
	if i := s.categoryIndex(category); i >= 0 {
		s.categories[i].score += points
		return
	}

	s.categories = append(s.categories, categoryScore{category: category, score: points})
}

// An absent or blank category means the name is the category. Shared with
// AddRequestScore so the rule lives in one place.
func scoreCategoryOf(name string, category []string) string {
	if len(category) > 0 {
		if c := strings.TrimSpace(category[0]); c != "" {
			return c
		}
	}

	return name
}

func scoreName(name string) string {
	if name = strings.TrimSpace(name); name == "" {
		return unspecifiedScoreReason
	}

	return name
}

func (s *RequestScore) Add(points int, name string, category ...string) int {
	name = scoreName(name)
	cat := scoreCategoryOf(name, category)

	if i := slices.IndexFunc(s.detections, func(d detection) bool {
		return d.name == name && d.category == cat
	}); i >= 0 {
		s.detections[i].score += points
	} else {
		s.detections = append(s.detections, detection{name: name, category: cat, score: points})
	}

	s.addToCategory(cat, points)

	return s.Total()
}

// Set forces a category to a value instead of accumulating toward one. The
// detections it overrides stay in the breakdown, so an alert can still show
// which signals fired and the operator can see why the two disagree.
//
// A later Add() accumulates on top of the forced value and keeps the override
// marker, because the score still is not the sum of its detections.
func (s *RequestScore) Set(points int, category string) int {
	category = strings.TrimSpace(category)

	if i := s.categoryIndex(category); i >= 0 {
		s.categories[i].score = points
		s.categories[i].override = true
	} else {
		s.categories = append(s.categories, categoryScore{category: category, score: points, override: true})
	}

	return s.Total()
}

func (s *RequestScore) Total() int {
	if s == nil {
		return 0
	}

	sum := 0

	for _, c := range s.categories {
		sum += c.score
	}

	return sum
}

func (s *RequestScore) For(category string) int {
	if s == nil {
		return 0
	}

	if i := s.categoryIndex(strings.TrimSpace(category)); i >= 0 {
		return s.categories[i].score
	}

	return 0
}

// Never nil: a rule doing `"x" in RequestScoreCategories()` runs on requests
// that have not been scored yet.
func (s *RequestScore) Categories() []string {
	out := []string{}

	if s == nil {
		return out
	}

	for _, c := range s.categories {
		out = append(out, c.category)
	}

	return out
}

func (s *RequestScore) Reasons() []string {
	if s == nil {
		return nil
	}

	out := make([]string, 0, len(s.detections))

	for _, d := range s.detections {
		out = append(out, d.key())
	}

	return out
}

// Lets the category hookvar stay absent when it would only repeat the reasons.
func (s *RequestScore) HasExplicitCategories() bool {
	if s == nil {
		return false
	}

	return slices.ContainsFunc(s.detections, func(d detection) bool {
		return d.category != d.name
	})
}

func (s *RequestScore) Empty() bool {
	return s == nil || len(s.detections) == 0
}

// What fired: "foobar:utc=12,foobar:cdp=50,slow_pow=5".
func (s *RequestScore) String() string {
	if s.Empty() {
		return ""
	}

	out := make([]string, 0, len(s.detections))

	for _, d := range s.detections {
		out = append(out, d.key()+"="+strconv.Itoa(d.score))
	}

	return strings.Join(out, ",")
}

// What the request is worth, per category: "foobar=0(set),slow_pow=5". The
// marker is why a category can sit below the detections listed for it in
// String().
func (s *RequestScore) CategoryDetail() string {
	if s == nil {
		return ""
	}

	out := make([]string, 0, len(s.categories))

	for _, c := range s.categories {
		entry := c.category + "=" + strconv.Itoa(c.score)
		if c.override {
			entry += "(set)"
		}

		out = append(out, entry)
	}

	return strings.Join(out, ",")
}
