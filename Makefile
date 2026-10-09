.PHONY: all build run test lint wire sqlc proto migrate-up migrate-down \
        docker-up docker-down docker-build clean gen-keys help

# ── Variables ──────────────────────────────────────────────────────────────────
BINARY_AUTH        := bin/auth-service
BINARY_WORKER      := bin/worker

CMD_AUTH           := ./cmd/server
CMD_WORKER         := ./cmd/worker

GO                 := go
GOFLAGS            := -trimpath
LDFLAGS            := -s -w

DOCKER_COMPOSE     := docker compose -f docker-compose.yml
MIGRATE_DIR        := ./migrations
DB_URL             ?= postgres://postgres:changeme@localhost:5432/authdb?sslmode=disable

# ── Build ──────────────────────────────────────────────────────────────────────

all: build

build: build-auth build-worker

build-auth:
	@echo "▶ Building auth service..."
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY_AUTH) $(CMD_AUTH)

build-worker:
	@echo "▶ Building worker..."
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY_WORKER) $(CMD_WORKER)

# ── Run ────────────────────────────────────────────────────────────────────────

run: build-auth
	@echo "▶ Starting auth service..."
	./$(BINARY_AUTH)

run-dev:
	@echo "▶ Starting auth service (live reload)..."
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
	@echo "▶ Protobuf source is in proto/auth/v1/auth.proto; generated stubs are not checked in"

gen-keys:
	@echo "▶ Generating RS256 key pair..."
	@mkdir -p certs
	openssl genrsa -out certs/private.pem 4096
	openssl rsa -in certs/private.pem -pubout -out certs/public.pem
	@echo "✔ Keys generated in ./certs/"

swagger:
	@echo "▶ Swagger generation is not configured yet"

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
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./...
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
	@echo "✔ Auth service:    http://localhost:8080"
	@echo "✔ Swagger UI:      http://localhost:8081"
	@echo "✔ Jaeger UI:       http://localhost:16686"
	@echo "✔ Grafana:         http://localhost:3000"
	@echo "✔ MailHog:         http://localhost:8025"

docker-down:
	$(DOCKER_COMPOSE) down -v

docker-logs:
	$(DOCKER_COMPOSE) logs -f auth postgres redis migrate

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
	@echo "  make run            Build + run auth service"
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
	@echo "  make docker-down    Stop Docker stack"
	@echo "  make clean          Remove build artifacts"
	@echo ""
