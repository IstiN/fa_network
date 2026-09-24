# syntax=docker/dockerfile:1
# Mirrors IstiN/auth: multi-stage Go build → minimal alpine runtime.
FROM golang:alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
# go.sum is globbed: builds before the first dependency lands still work.
COPY go.mod go.sum* ./
COPY . .
# GOTOOLCHAIN=auto (default) fetches the exact version go.mod requires.
RUN go mod download && CGO_ENABLED=0 go build -o /fa-network ./cmd/server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /fa-network /usr/local/bin/fa-network
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/fa-network"]
