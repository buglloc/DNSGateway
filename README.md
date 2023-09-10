DNSGateway
==========

Basically I needed two things:
  - manage local records for [AdGuard Home](https://adguard.com/en/adguard-home/overview.html)
  - make certbot DNS validation more secure (i.e. don't store API token on _every_ ingress machine)

That's how DNSGateway appeared. Basic features:
  - act as an RFC 2136 server
  - send update sets to AdGuard Home or Cloudflare
  - that's all :)
