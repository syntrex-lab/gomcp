FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /syntrex-proxy ./cmd/syntrex-proxy/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /syntrex-proxy /usr/local/bin/syntrex-proxy
EXPOSE 8080
ENTRYPOINT ["syntrex-proxy"]
CMD ["--listen", ":8080", "--target", "https://api.openai.com", "--mode", "block"]
