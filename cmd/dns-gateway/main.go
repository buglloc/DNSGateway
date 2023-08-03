package main

import (
	"fmt"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/buglloc/DNSGateway/internal/commands"
	_ "go.uber.org/automaxprocs"
	"os"
)

// Syntax: https://github.com/AdguardTeam/AdGuardHome/wiki/Hosts-Blocklists#adblock-style
//// examples:
////    ||4.3.2.1.in-addr.arpa^$dnsrewrite=NOERROR;PTR;example.net.
////    ||2.0.0.0.0.0.0.0.4.f.7.0.0.0.0.0.0.0.4.3.0.0.0.0.8.b.6.0.2.0.a.2.ip6.arpa^$dnsrewrite=NOERROR;PTR;example.net.
////    ||ya.ru^$dnsrewrite=NOERROR;A;1.2.3.3
////    ||ya.ru^$dnsrewrite=NOERROR;AAAA;::1
//
//NewNetworkRule

func main() {
	rr, err := rules.NewNetworkRule("||ya.ru^$dnsrewrite=NOERROR;AAAA;::1", 0)
	fmt.Println(rr.DNSRewrite.RRType, err)
	os.Exit(0)
	if err := commands.Execute(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
