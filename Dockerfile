FROM golang:1.24-alpine AS builder

WORKDIR /src

RUN apk add --no-cache git

COPY go.mod ./
COPY . .

RUN go build -o /out/auth-service ./cmd/server

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /out/auth-service /usr/local/bin/auth-service
COPY configs ./configs

EXPOSE 8080 9090

ENV CONFIG_PATH=/app/configs/app.yaml

ENTRYPOINT ["/usr/local/bin/auth-service"]
