package appsec

import (
	"strconv"
	"strings"
)

const unspecifiedScoreReason = "unspecified"

type RequestScore struct {
	total    int
	order    []string
	byReason map[string]int
}

func (s *RequestScore) Add(points int, reason string) int {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = unspecifiedScoreReason
	}

	if s.byReason == nil {
		s.byReason = make(map[string]int)
	}

	if _, seen := s.byReason[reason]; !seen {
		s.order = append(s.order, reason)
	}

	s.byReason[reason] += points
	s.total += points

	return s.total
}

func (s *RequestScore) Total() int {
	if s == nil {
		return 0
	}

	return s.total
}

func (s *RequestScore) For(reason string) int {
	if s == nil {
		return 0
	}

	return s.byReason[strings.TrimSpace(reason)]
}

func (s *RequestScore) Reasons() []string {
	if s == nil || len(s.order) == 0 {
		return nil
	}

	out := make([]string, len(s.order))
	copy(out, s.order)

	return out
}

func (s *RequestScore) Empty() bool {
	return s == nil || len(s.order) == 0
}

func (s *RequestScore) String() string {
	if s.Empty() {
		return ""
	}

	var b strings.Builder

	for i, reason := range s.order {
		if i > 0 {
			b.WriteByte(',')
		}

		b.WriteString(reason)
		b.WriteByte('=')
		b.WriteString(strconv.Itoa(s.byReason[reason]))
	}

	return b.String()
}
