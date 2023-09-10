package ucloudflare

type Option func(*Upstream)

func WithZoneID(zoneID string) Option {
	return func(client *Upstream) {
		client.zoneID = zoneID
	}
}
