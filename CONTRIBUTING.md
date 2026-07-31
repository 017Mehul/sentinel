# Contributing

Pull requests are welcome. Here's how to get set up.

## Prerequisites

- Go 1.24+
- Docker (needed for integration tests)
- `golangci-lint` — `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`
- `gosec` — `go install github.com/securego/gosec/v2/cmd/gosec@latest`
- `govulncheck` — `go install golang.org/x/vuln/cmd/govulncheck@latest`
- `migrate` CLI — https://github.com/golang-migrate/migrate/releases

## Setup

```bash
git clone https://github.com/MehulChamoli/auth-service.git
cd auth-service
go mod tidy
make gen-keys
cp .env.example .env
```

## Running tests

```bash
make test                # unit tests, no external deps needed
make test-cover          # with coverage
make test-integration    # needs Docker
make lint
make security
```

## Code style

- Run `gofmt` / `goimports` before pushing — CI will catch it if you don't.
- Exported symbols need GoDoc comments.
- Wrap external errors with `fmt.Errorf("context: %w", err)`.
- Never store raw tokens — always SHA-256 hash them first.
- Repository methods should accept a `dbTX` interface so callers can compose multiple operations in a single transaction.

## Sending a PR

1. Fork and branch: `git checkout -b feat/your-thing`
2. Write tests for new behaviour.
3. Make sure `make test lint` passes.
4. Open a PR against `main`. Describe what changed and why — the diff alone usually isn't enough context.

## Adding migrations

```bash
make migrate-create NAME=your_migration_name
```

This creates both `.up.sql` and `.down.sql` files. Always fill in the down migration so it can be rolled back cleanly.

## Security issues

Don't open a public issue for security vulnerabilities. Email directly so it can be looked at before anything goes public.
