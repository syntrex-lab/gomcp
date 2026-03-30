# syntax=docker/dockerfile:1
# Syntrex GoMCP — Multi-stage build

# ─── Build stage ────────────────────────────────────
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build static binary (modernc/sqlite = pure Go, no CGO needed).
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /gomcp ./cmd/gomcp

# ─── Runtime stage ──────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /gomcp /app/gomcp

# RUN addgroup -S syntrex && adduser -S syntrex -G syntrex
# RUN mkdir -p /data/.rlm && chown -R syntrex:syntrex /data
# USER syntrex

EXPOSE 9750

ENV RLM_DIR=/data/.rlm
ENV GOMCP_HTTP_PORT=9750

ENTRYPOINT ["/app/gomcp"]
CMD ["--http-port", "9750"]
