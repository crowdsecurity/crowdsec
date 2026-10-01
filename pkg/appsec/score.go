package appsec

import (
	"slices"
	"strconv"
	"strings"
)

// Authoritative for scoring. Insertion-ordered.
type categoryScore struct {
	category string
	score    int
	// Only used by Set() to mark the score that was overriden.
	override bool
}

// One single detection with its category and score.
type detection struct {
	name     string
	category string
	score    int
}

// Render a detection, use the name if not category is set.
func (d detection) key() string {
	if d.category == d.name {
		return d.name
	}

	return d.category + ":" + d.name
}

// This is the full representation of a request's score.
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

// An absent or blank category means the name is the category.
func (s *RequestScore) Add(points int, name string, category ...string) int {
	cat := name

	if len(category) > 0 && category[0] != "" {
		cat = category[0]
	}

	// if the detection already exists, increment its score
	if i := slices.IndexFunc(s.detections, func(d detection) bool {
		return d.name == name && d.category == cat
	}); i >= 0 {
		s.detections[i].score += points
	} else {
		s.detections = append(s.detections, detection{name: name, category: cat, score: points})
	}

	// update the category score
	s.addToCategory(cat, points)

	return s.Total()
}

// Set overrides a category's score with a fixed value (and mark it explicitely)
func (s *RequestScore) Set(points int, category string) int {
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

	if i := s.categoryIndex(category); i >= 0 {
		return s.categories[i].score
	}

	return 0
}

// never nil to allow "x" in Categories()
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

// never nil to allow "x" in Reasons()
func (s *RequestScore) Reasons() []string {
	out := []string{}

	if s == nil {
		return out
	}

	// reuse the previously declared out slice
	out = make([]string, 0, len(s.detections))

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
