package xhttp

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/buglloc/certifi"
)

const (
	dialTimeout    = 1 * time.Second
	requestTimeout = 5 * time.Second
	keepAlive      = 60 * time.Second
)

func NewHTTPClient() *http.Client {
	return &http.Client{
		Transport: NewTransport(),
		Timeout:   requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func NewTransport() http.RoundTripper {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = NewTLSClientConfig()
	transport.DialContext = (&net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: keepAlive,
	}).DialContext
	return transport
}

func NewTLSClientConfig() *tls.Config {
	return &tls.Config{
		RootCAs: certifi.NewCertPool(),
	}
}
