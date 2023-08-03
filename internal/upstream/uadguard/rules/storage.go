package rules

import (
	"sort"

	"github.com/buglloc/DNSGateway/internal/upstream"
)

type StoreKey struct {
	Name string
	Type upstream.RType
}

type Storage struct {
	before []string
	after  []string
	rules  map[StoreKey]Rule
}

func NewStoreKey(name string, typ upstream.RType) StoreKey {
	return StoreKey{
		Name: name,
		Type: typ,
	}
}

func (s *Storage) ByKey(key StoreKey) (Rule, bool) {
	r, ok := s.rules[key]
	return r, ok
}

func (s *Storage) ByName(name string, typ upstream.RType) (Rule, bool) {
	r, ok := s.rules[StoreKey{name, typ}]
	return r, ok
}

func (s *Storage) Delete(r Rule) {
	delete(s.rules, r.Key())
}

func (s *Storage) Set(r Rule) {
	s.rules[r.Key()] = r
}

func (s *Storage) Dump() []string {
	out := make([]string, len(s.before))
	copy(out, s.before)

	rules := make([]string, 0, len(s.rules))
	for _, rule := range s.rules {
		rules = append(rules, rule.Format())
	}

	sort.Strings(rules)
	for _, rule := range rules {
		out = append(out, rule)
	}

	for _, rule := range s.after {
		out = append(out, rule)
	}

	return out
}
