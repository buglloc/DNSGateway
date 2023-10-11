package uadguard_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/buglloc/DNSGateway/internal/upstream"
	"github.com/buglloc/DNSGateway/internal/upstream/uadguard"
)

func TestSrvMock(t *testing.T) {
	var adghMux http.ServeMux
	var rulesMu sync.Mutex
	rules := []string{
		"lol",
		"kek",
		"|ya.ru^$dnsrewrite=NOERROR;A;1.2.3.3",
		"# ---- DNSGateway rules begin ----",
		"|ya.ru^$dnsrewrite=NOERROR;A;1.2.3.3",
		"|3.3.2.1.in-addr.arpa^$dnsrewrite=NOERROR;PTR;ya.ru",
		"# ---- DNSGateway rules end ----",
		"|ya.ru^$dnsrewrite=NOERROR;A;1.2.3.3",
		"kek",
		"lol",
	}

	adghMux.HandleFunc("/control/filtering/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET expected", http.StatusBadRequest)
			return
		}

		rulesMu.Lock()
		defer rulesMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			Rules    []string `json:"user_rules"`
			Internal int      `json:"interval"`
			Enabled  bool     `json:"enabled"`
		}{
			Rules:    rules,
			Internal: 24,
			Enabled:  true,
		})
	})

	adghMux.HandleFunc("/control/filtering/set_rules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST expected", http.StatusBadRequest)
			return
		}

		var req struct {
			Rules []string `json:"rules"`
		}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		rulesMu.Lock()
		rules = req.Rules
		rulesMu.Unlock()

		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(&adghMux)
	defer srv.Close()

	c, err := uadguard.NewUpstream(
		uadguard.WithUpstream(srv.URL),
		uadguard.WithAutoPTR(true),
	)
	require.NoError(t, err)

	rr, err := c.Query(context.Background(), upstream.Rule{
		Name: "lol",
		Type: dns.TypePTR,
	})
	require.NoError(t, err)
	require.Len(t, rr, 0)

	rr, err = c.Query(context.Background(), upstream.Rule{
		Name: "ya.ru.",
		Type: dns.TypeA,
	})
	require.NoError(t, err)
	require.Len(t, rr, 1)
	re := upstream.Rule{
		Name:     "ya.ru.",
		Type:     dns.TypeA,
		Value:    net.ParseIP("1.2.3.3"),
		ValueStr: "1.2.3.3",
	}
	require.EqualValues(t, re, rr[0])

	rr, err = c.Query(context.Background(), upstream.Rule{
		Type:     dns.TypePTR,
		ValueStr: "ya.ru.",
	})
	require.NoError(t, err)
	require.Len(t, rr, 1)
	re = upstream.Rule{
		Name:     "3.3.2.1.in-addr.arpa.",
		Type:     dns.TypePTR,
		Value:    "ya.ru.",
		ValueStr: "ya.ru.",
	}
	require.EqualValues(t, re, rr[0])

	axfrRules, err := c.Query(context.Background(), upstream.Rule{Type: dns.TypeAXFR})
	require.NoError(t, err)
	expectedAXFRRules := []upstream.Rule{
		upstream.Rule{
			Name:     "ya.ru.",
			Type:     dns.TypeA,
			Value:    net.ParseIP("1.2.3.3"),
			ValueStr: "1.2.3.3",
		},
		{
			Name:     "3.3.2.1.in-addr.arpa.",
			Type:     dns.TypePTR,
			Value:    "ya.ru.",
			ValueStr: "ya.ru.",
		},
	}
	require.EqualValues(t, expectedAXFRRules, axfrRules)

	tx, err := c.Tx(context.Background())
	require.NoError(t, err)

	err = tx.Delete(upstream.Rule{
		Name: "ya.ru.",
		Type: dns.TypeA,
	})
	require.NoError(t, err)

	err = tx.Append(upstream.Rule{
		Name:  "ya.ru.",
		Type:  dns.TypeA,
		Value: net.ParseIP("1.2.4.5"),
	})
	require.NoError(t, err)

	err = tx.Commit(context.Background())
	require.NoError(t, err)

	expected := []string{
		"lol",
		"kek",
		"|ya.ru^$dnsrewrite=NOERROR;A;1.2.3.3",
		"# ---- DNSGateway rules begin ----",
		"|ya.ru^$dnsrewrite=NOERROR;A;1.2.4.5",
		"|5.4.2.1.in-addr.arpa^$dnsrewrite=NOERROR;PTR;ya.ru",
		"# ---- DNSGateway rules end ----",
		"|ya.ru^$dnsrewrite=NOERROR;A;1.2.3.3",
		"kek",
		"lol",
	}

	require.EqualValues(t, expected, rules)
}
