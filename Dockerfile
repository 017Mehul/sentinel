FROM golang:1.26.9-alpine AS builder

WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/sentinel ./cmd/server

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata wget \
    && addgroup -S sentinel \
    && adduser -S -G sentinel -h /app sentinel

WORKDIR /app

COPY --from=builder /out/sentinel /usr/local/bin/sentinel
COPY --chown=sentinel:sentinel configs ./configs

USER sentinel

EXPOSE 8080 9090

ENV CONFIG_PATH=/app/configs/app.yaml

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
  CMD wget -q -O - http://127.0.0.1:8080/healthz >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/sentinel"]
