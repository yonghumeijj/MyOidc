FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/gooidc .

FROM alpine:3.22

RUN adduser -D -H app
WORKDIR /app
COPY --from=builder /out/gooidc /app/gooidc
RUN mkdir -p /data && chown -R app:app /data

USER app
EXPOSE 8080
ENV ADDR=:8080
ENV DATA_DIR=/data

ENTRYPOINT ["/app/gooidc"]
