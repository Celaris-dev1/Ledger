FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/ledgerd ./cmd/ledgerd && CGO_ENABLED=0 go build -o /out/ledger ./cmd/ledger

FROM alpine:3.20
# git: external anchoring to a git repo; ca-certificates: RFC 3161 TSAs over https
RUN apk add --no-cache git ca-certificates && adduser -D -u 10001 ledger && mkdir -p /data && chown ledger /data
COPY --from=build /out/ /usr/local/bin/
USER ledger
WORKDIR /data
ENV LEDGER_ADDR=:8410 LEDGER_KEY_FILE=/data/ledger_ed25519.key LEDGER_ANCHOR_DIR=/data/anchors
EXPOSE 8410
ENTRYPOINT ["ledgerd"]
