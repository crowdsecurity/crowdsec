package appsec

import (
	"slices"
	"strconv"
	"strings"
)

const (
	unspecifiedScoreReason = "unspecified"
	// Label of the entry Set() appends to record what it forced a score to.
	// Distinct from any plausible operator-chosen label so the breakdown
	// stays unambiguous about which points came from a signal.
	scoreSetLabel = "set"
)

// Entries are keyed by (label, category): re-adding a pair accumulates in
// place, so the reported order stays stable across a request.
type scoreEntry struct {
	label    string
	category string
	points   int
	// An override entry records the value Set() forced. Add() must not
	// accumulate into one, so it is flagged rather than matched by label.
	override bool
	// Superseded entries no longer count toward any total, but stay in the
	// breakdown: an override changes what the signals are worth, not the
	// fact that they fired. Erasing them would leave an alert unable to say
	// why the request was scored.
	superseded bool
}

// key is how the entry appears in the breakdown. A signal that never named a
// category is its own category, so the prefix would just repeat the label:
// dropping it is also what every pre-category config already emits.
func (e scoreEntry) key() string {
	if e.category == e.label {
		return e.label
	}

	return e.category + ":" + e.label
}

func (e scoreEntry) counts() bool {
	return !e.superseded
}

// RequestScore accumulates per-request suspicion points on two axes: a label
// (the signal that fired) and a category (the family it belongs to). The
// entry list is the only source of truth — every accessor derives from it, so
// there is no second index that can drift out of sync.
//
// Every entry has a category: a signal that names none is filed under its own
// label. Categories therefore partition the live entries, so the per-category
// scores always add up to the total.
//
// The label axis is a record of what fired and keeps entries an override has
// superseded; the category axis and the total are what the request is
// currently worth. So the breakdown deliberately does not sum to the total
// once Set() has been used.
type RequestScore struct {
	total   int
	entries []scoreEntry
}

func normalizeScoreName(v, fallback string) string {
	if v = strings.TrimSpace(v); v == "" {
		return fallback
	}

	return v
}

// Defaults to the label, so a rule that never heard of categories can still be
// read back with RequestScore("cdp").
//
// The expr prototypes already cap the category at one value, so extras are
// ignored rather than rejected: a Go-side caller must not be able to trip a
// runtime error no rule author wrote.
func scoreCategoryArg(category []string, label string) string {
	if len(category) == 0 {
		return label
	}

	return normalizeScoreName(category[0], label)
}

func (s *RequestScore) indexOf(label, category string) int {
	return slices.IndexFunc(s.entries, func(e scoreEntry) bool {
		return e.counts() && !e.override && e.label == label && e.category == category
	})
}

func (s *RequestScore) Add(points int, reason string, category ...string) int {
	label := normalizeScoreName(reason, unspecifiedScoreReason)
	cat := scoreCategoryArg(category, label)

	if i := s.indexOf(label, cat); i >= 0 {
		s.entries[i].points += points
	} else {
		s.entries = append(s.entries, scoreEntry{label: label, category: cat, points: points})
	}

	s.total += points

	return s.total
}

// Set forces a score to a value instead of accumulating toward one. The
// entries it overrides stop counting but stay in the breakdown, so an alert
// can still show which signals fired. Each named category is set to points,
// so Set(50, "a", "b") leaves a total of 100, not 50.
func (s *RequestScore) Set(points int, categories ...string) int {
	if len(categories) == 0 {
		s.supersede(func(scoreEntry) bool { return true })
		s.override(scoreSetLabel, points)

		return s.retotal()
	}

	for _, raw := range categories {
		// Naming no category at all is how you reset the whole score, so an
		// empty one must not silently do that: skip it. The caller warns.
		cat := strings.TrimSpace(raw)
		if cat == "" {
			continue
		}

		s.supersede(func(e scoreEntry) bool { return e.category == cat })
		s.override(cat, points)
	}

	return s.retotal()
}

func (s *RequestScore) override(category string, points int) {
	s.entries = append(s.entries, scoreEntry{
		label:    scoreSetLabel,
		category: category,
		points:   points,
		override: true,
	})
}

func (s *RequestScore) supersede(match func(scoreEntry) bool) {
	for i := range s.entries {
		if match(s.entries[i]) {
			s.entries[i].superseded = true
		}
	}
}

func (s *RequestScore) retotal() int {
	s.total = 0

	for _, e := range s.entries {
		if e.counts() {
			s.total += e.points
		}
	}

	return s.total
}

func (s *RequestScore) Total() int {
	if s == nil {
		return 0
	}

	return s.total
}

// Reports what the signal claimed, even where an override has since stopped
// those points counting — the label axis is the record of what fired.
func (s *RequestScore) For(reason string) int {
	if s == nil {
		return 0
	}

	label := strings.TrimSpace(reason)
	sum := 0

	for _, e := range s.entries {
		if e.label == label {
			sum += e.points
		}
	}

	return sum
}

// No argument means no filter, so RequestScore() keeps the meaning it
// shipped with. Superseded entries are excluded: this is the live value.
func (s *RequestScore) ForCategories(categories ...string) int {
	if s == nil {
		return 0
	}

	if len(categories) == 0 {
		return s.total
	}

	// An empty name is not a category, so it matches nothing, exactly like
	// any name never used — one meaning per spelling.
	wanted := make([]string, 0, len(categories))

	for _, c := range categories {
		if c = strings.TrimSpace(c); c != "" {
			wanted = append(wanted, c)
		}
	}

	sum := 0

	for _, e := range s.entries {
		if e.counts() && slices.Contains(wanted, e.category) {
			sum += e.points
		}
	}

	return sum
}

func (s *RequestScore) Reasons() []string {
	return s.distinct(scoreEntry.key)
}

// Ordered by where the category first appeared, superseded entries included,
// so an override does not shuffle a category to the back of the list. A
// category with nothing live left is dropped rather than shown at zero.
func (s *RequestScore) Categories() []string {
	if s == nil {
		return nil
	}

	out := make([]string, 0, len(s.entries))

	for _, e := range s.entries {
		if slices.Contains(out, e.category) {
			continue
		}

		if slices.ContainsFunc(s.entries, func(o scoreEntry) bool {
			return o.counts() && o.category == e.category
		}) {
			out = append(out, e.category)
		}
	}

	return out
}

func (s *RequestScore) distinct(key func(scoreEntry) string) []string {
	if s == nil || len(s.entries) == 0 {
		return nil
	}

	out := make([]string, 0, len(s.entries))

	for _, e := range s.entries {
		if k := key(e); !slices.Contains(out, k) {
			out = append(out, k)
		}
	}

	return out
}

// Whether any rule actually grouped a signal under a different name. Lets the
// category alert context stay absent when it would only repeat the reasons.
func (s *RequestScore) HasExplicitCategories() bool {
	if s == nil {
		return false
	}

	return slices.ContainsFunc(s.entries, func(e scoreEntry) bool {
		return e.counts() && e.category != e.label
	})
}

func (s *RequestScore) Empty() bool {
	return s == nil || len(s.entries) == 0
}

func (s *RequestScore) String() string {
	return s.detail(s.Reasons(), s.forKey)
}

func (s *RequestScore) forKey(key string) int {
	sum := 0

	for _, e := range s.entries {
		if e.key() == key {
			sum += e.points
		}
	}

	return sum
}

func (s *RequestScore) CategoryDetail() string {
	return s.detail(s.Categories(), func(c string) int { return s.ForCategories(c) })
}

func (s *RequestScore) detail(keys []string, sum func(string) int) string {
	if s.Empty() {
		return ""
	}

	var b strings.Builder

	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}

		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strconv.Itoa(sum(k)))
	}

	return b.String()
}
