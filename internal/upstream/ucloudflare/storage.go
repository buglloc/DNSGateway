package ucloudflare

import (
	"fmt"

	"github.com/cloudflare/cloudflare-go"

	"github.com/buglloc/DNSGateway/internal/upstream"
)

type Storage struct {
	rules    []Rule
	toDelete []cloudflare.DNSRecord
	toAdd    []cloudflare.DNSRecord
}

func NewCFStorage(records []cloudflare.DNSRecord) (*Storage, error) {
	var s Storage
	for _, r := range records {
		rule, err := RuleFromCF(r)
		if err != nil {
			return nil, fmt.Errorf("invalid rule: %w", err)
		}

		s.rules = append(s.rules, rule)
	}

	return &s, nil
}

func (s *Storage) Rules() []upstream.Rule {
	out := make([]upstream.Rule, len(s.rules))
	for i, r := range s.rules {
		out[i] = r.upRecord
	}

	return out
}

func (s *Storage) Query(q upstream.Rule) []upstream.Rule {
	var out []upstream.Rule
	for _, rule := range s.rules {
		if !rule.SameUpstream(q) {
			continue
		}

		out = append(out, rule.upRecord)
	}

	return out
}

func (s *Storage) Delete(q upstream.Rule) ([]upstream.Rule, error) {
	n := 0
	var deleted []upstream.Rule
	for _, rule := range s.rules {
		if rule.SameUpstream(q) {
			deleted = append(deleted, rule.upRecord)
			if rule.cfRecord.ID != "" {
				s.toDelete = append(s.toDelete, rule.cfRecord)
			}
			continue
		}

		s.rules[n] = rule
		n++
	}

	s.rules = s.rules[:n]
	return deleted, nil
}

func (s *Storage) Append(r upstream.Rule) error {
	rule, err := RuleFromUpstream(r)
	if err != nil {
		return err
	}

	s.rules = append(s.rules, rule)
	s.toAdd = append(s.toAdd, rule.cfRecord)
	return nil
}

func (s *Storage) ToDelete() []cloudflare.DNSRecord {
	return s.toDelete
}

func (s *Storage) ToAdd() []cloudflare.DNSRecord {
	return s.toAdd
}
