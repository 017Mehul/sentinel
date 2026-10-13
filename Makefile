.PHONY: all build run test lint wire sqlc proto migrate-up migrate-down \
        docker-up docker-down docker-reset docker-logs docker-build clean gen-keys help

# ── Variables ──────────────────────────────────────────────────────────────────
ifneq ($(wildcard .env),)
include .env
export
endif

BINARY_AUTH        := bin/sentinel
BINARY_WORKER      := bin/sentinel-worker

CMD_AUTH           := ./cmd/server
CMD_WORKER         := ./cmd/worker

GO                 := go
GOFLAGS            := -trimpath
LDFLAGS            := -s -w

DOCKER_COMPOSE     := docker compose -f docker-compose.yml
MIGRATE_DIR        := ./migrations
DB_PASSWORD        ?= changeme
DB_URL             ?= postgres://postgres:$(DB_PASSWORD)@localhost:5432/authdb?sslmode=disable

# ── Build ──────────────────────────────────────────────────────────────────────

all: build

build: build-auth build-worker

build-auth:
	@echo "▶ Building Sentinel API..."
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY_AUTH) $(CMD_AUTH)

build-worker:
	@echo "▶ Building worker..."
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY_WORKER) $(CMD_WORKER)

# ── Run ────────────────────────────────────────────────────────────────────────

run: build-auth
	@echo "▶ Starting Sentinel API..."
	./$(BINARY_AUTH)

run-dev:
	@echo "▶ Starting Sentinel API (live reload)..."
	air -c .air.toml

run-worker: build-worker
	./$(BINARY_WORKER)

# ── Code Generation ────────────────────────────────────────────────────────────

wire:
	@echo "▶ wire_gen.go is hand-maintained in cmd/server/ — no generation step needed"
	@echo "  To regenerate: wire ./cmd/server/ (requires: go install github.com/google/wire/cmd/wire@latest)"

sqlc:
	@echo "▶ No sqlc queries are currently defined"

proto:
	@echo "▶ Protobuf source: proto/auth/v1/auth.proto"
	@echo "▶ Generated Go bindings are checked in under proto/auth/v1/"
	@command -v protoc >/dev/null || (echo "protoc is required to regenerate bindings" && exit 1)
	@command -v protoc-gen-go >/dev/null || (echo "install protoc-gen-go first" && exit 1)
	@command -v protoc-gen-go-grpc >/dev/null || (echo "install protoc-gen-go-grpc first" && exit 1)
	protoc --go_out=. --go_opt=module=github.com/017Mehul/sentinel --go-grpc_out=. --go-grpc_opt=module=github.com/017Mehul/sentinel proto/auth/v1/auth.proto

gen-keys:
	@echo "▶ Generating RS256 key pair..."
	@mkdir -p certs
	openssl genrsa -out certs/private.pem 4096
	openssl rsa -in certs/private.pem -pubout -out certs/public.pem
	@echo "✔ Keys generated in ./certs/"

swagger:
	@echo "▶ OpenAPI contract: docs/api/openapi.yaml"

# ── Database ───────────────────────────────────────────────────────────────────

migrate-up:
	@echo "▶ Running migrations (up)..."
	migrate -path $(MIGRATE_DIR) -database "$(DB_URL)" up

migrate-down:
	@echo "▶ Rolling back last migration..."
	migrate -path $(MIGRATE_DIR) -database "$(DB_URL)" down 1

migrate-force:
	@echo "▶ Forcing migration version $(VERSION)..."
	migrate -path $(MIGRATE_DIR) -database "$(DB_URL)" force $(VERSION)

migrate-status:
	migrate -path $(MIGRATE_DIR) -database "$(DB_URL)" version

migrate-create:
	@echo "▶ Creating migration: $(NAME)..."
	migrate create -ext sql -dir $(MIGRATE_DIR) -seq $(NAME)

# ── Testing ────────────────────────────────────────────────────────────────────

test:
	@echo "▶ Running all tests (race detector)..."
	$(GO) test -race -count=1 -timeout=120s ./...

test-unit:
	@echo "▶ Running unit tests..."
	$(GO) test -race -count=1 -timeout=60s ./tests/unit/... ./internal/... ./pkg/...

test-integration:
	@echo "▶ Running integration tests (requires Docker)..."
	$(GO) test -race -count=1 -timeout=300s -tags=integration ./tests/integration/...

test-cover:
	@echo "▶ Running tests with coverage..."
	$(GO) test -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "✔ Coverage report: coverage.html"

bench:
	@echo "▶ Running benchmarks..."
	$(GO) test -bench=. -benchmem -benchtime=5s ./tests/benchmarks/...

# ── Lint ───────────────────────────────────────────────────────────────────────

lint:
	@echo "▶ Running golangci-lint..."
	golangci-lint run ./... --timeout=5m

lint-fix:
	golangci-lint run --fix ./...

vet:
	$(GO) vet ./...

# ── Security ───────────────────────────────────────────────────────────────────

security:
	@echo "▶ Running gosec..."
	gosec ./...
	@echo "▶ Running govulncheck..."
	govulncheck ./...

# ── Docker ─────────────────────────────────────────────────────────────────────

docker-build:
	@echo "▶ Building Docker images..."
	docker build -t sentinel:latest .

docker-up:
	@echo "▶ Starting full stack..."
	$(DOCKER_COMPOSE) up --build -d
	@echo "✔ Sentinel API:    http://localhost:8080"
	@echo "✔ Redis:           localhost:6379"
	@echo "✔ gRPC:            localhost:9090"
	@echo "✔ Jaeger UI:       http://localhost:16686"
	@echo "✔ Mailpit UI:      http://localhost:8025"

docker-down:
	$(DOCKER_COMPOSE) down

docker-reset:
	@echo "⚠ This removes local PostgreSQL data."
	$(DOCKER_COMPOSE) down -v

docker-logs:
	$(DOCKER_COMPOSE) logs -f api worker postgres redis mailpit migrate jaeger

# ── Cleanup ────────────────────────────────────────────────────────────────────

clean:
	@echo "▶ Cleaning..."
	rm -rf bin/ coverage.out coverage.html
	$(GO) clean -testcache

tidy:
	$(GO) mod tidy
	$(GO) mod verify

# ── Help ───────────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "Sentinel — Available Make Targets"
	@echo "═══════════════════════════════════════"
	@echo "  make build          Build all binaries"
	@echo "  make run            Build + run Sentinel API"
	@echo "  make wire           Regenerate Wire DI code"
	@echo "  make sqlc           Regenerate sqlc query code"
	@echo "  make proto          Regenerate protobuf code"
	@echo "  make gen-keys       Generate RS256 key pair"
	@echo "  make migrate-up     Run all pending migrations"
	@echo "  make migrate-down   Rollback last migration"
	@echo "  make test           Run all unit tests"
	@echo "  make test-unit      Run unit tests only"
	@echo "  make test-integration  Run Testcontainers integration tests"
	@echo "  make test-cover     Run tests + coverage report"
	@echo "  make bench          Run benchmarks"
	@echo "  make lint           Run golangci-lint"
	@echo "  make security       Run gosec + govulncheck"
	@echo "  make docker-up      Start full Docker stack"
	@echo "  make docker-down    Stop Docker stack (preserve data)"
	@echo "  make clean          Remove build artifacts"
	@echo ""
