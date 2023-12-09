FROM golang:1.21.5 as build

WORKDIR /go/src/app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/dns-gateway ./cmd/dns-gateway

FROM debian:bookworm-slim

COPY --from=build /go/bin/dns-gateway /usr/sbin/dns-gateway

ENTRYPOINT ["/usr/sbin/dns-gateway"]
