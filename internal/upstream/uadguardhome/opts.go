package uadguardhome

type Option func(*Upstream)

func WithUpstream(upstream string) Option {
	return func(client *Upstream) {
		if upstream == "" {
			return
		}

		client.httpc.SetBaseURL(upstream)
	}
}

func WithBasicAuth(login, password string) Option {
	return func(client *Upstream) {
		client.httpc.SetBasicAuth(login, password)
	}
}

func WithAutoPTR(enabled bool) Option {
	return func(client *Upstream) {
		client.autoPTR = enabled
	}
}

func WithDebug(verbose bool) Option {
	return func(client *Upstream) {
		client.httpc.SetDebug(verbose)
	}
}
