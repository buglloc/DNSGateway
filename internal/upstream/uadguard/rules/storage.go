package rules

import (
	"github.com/buglloc/DNSGateway/internal/upstream"
)

type Storage struct {
	before []string
	after  []string
	rules  []Rule
}

func (s *Storage) Query(q upstream.Rule) []upstream.Rule {
	var out []upstream.Rule
	for _, rule := range s.rules {
		if !rule.SameUpstreamRule(&q) {
			continue
		}

		out = append(out, *rule.Rule)
	}

	return out
}

func (s *Storage) Delete(q upstream.Rule) []upstream.Rule {
	n := 0
	var deleted []upstream.Rule
	for _, rule := range s.rules {
		if rule.SameUpstreamRule(&q) {
			deleted = append(deleted, *rule.Rule)
			continue
		}

		s.rules[n] = rule
		n++
	}

	s.rules = s.rules[:n]
	return deleted
}

func (s *Storage) Append(r upstream.Rule) {
	s.rules = append(s.rules, Rule{
		Rule: &r,
	})
}

func (s *Storage) Dump() []string {
	out := make([]string, len(s.before))
	copy(out, s.before)

	for _, rule := range s.rules {
		out = append(out, rule.Format())
	}

	return append(out, s.after...)
}
