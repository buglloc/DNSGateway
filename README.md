DNSGateway
==========

Basically I needed two things:
  - manage local records for [AdGuard Home](https://adguard.com/en/adguard-home/overview.html)
  - make certbot DNS validation more secure (i.e. don't store API token on _every_ ingress machine)

That's how DNSGateway appeared. Basic features:
  - act as an RFC 2136 server
  - send update sets to AdGuard Home or Cloudflare
  - that's all :)

Related posts:
  - [DNSGateway + Cloudflare to issue Let’s Encrypt certificates with DNS-01 challenges](https://ut.buglloc.com/2023/09/dnsgateway-acme/)
  - [ExternalDNS + AdGuard Home + CoreDNS => ExternalDNS + DNSGateway + AdGuard Home](https://ut.buglloc.com/2023/09/bye-coredns/)
