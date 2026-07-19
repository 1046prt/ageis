FROM golang:1.22-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /build/secrets-daemon ./cmd/daemon
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /build/secrets-cli ./cmd/cli

FROM alpine:3.19

RUN apk add --no-cache ca-certificates && \
    adduser -D -u 1000 secrets

COPY --from=builder /build/secrets-daemon /usr/local/bin/
COPY --from=builder /build/secrets-cli /usr/local/bin/

RUN mkdir -p /etc/secrets-manager /data && chown secrets:secrets /data
USER secrets

EXPOSE 8443

ENTRYPOINT ["secrets-daemon"]
CMD ["-db", "/data/secrets.db"]
