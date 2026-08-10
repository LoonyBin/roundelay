.PHONY: all test vectors codes generate conformance check fmt pg-up pg-down pg-test

all: check

# Regenerate the frozen vectors. A diff here is a change to the
# cross-implementation contract — review it as one.
vectors:
	go run ./internal/vectorgen ./vectors

# Regenerate the refusal vocabulary from the document. A diff here means the
# code list moved, which is a protocol change.
codes:
	go run ./internal/codegen/codesgen
	gofmt -w codes/codes.go

generate: vectors codes

# The lints the README says a conforming release runs.
conformance:
	go run ./internal/conformance/cmd/conformance-lint

test:
	go test ./...

# The Postgres store's tests need a database. Without ROUNDELAY_TEST_DSN they
# skip, so `make test` stays runnable anywhere — but a release that has not run
# them has not tested the store it ships.
PG_DSN ?= postgres://postgres:roundelay@127.0.0.1:55432/roundelay?sslmode=disable

pg-up:
	podman run -d --rm --name roundelay-pg \
		-e POSTGRES_PASSWORD=roundelay -e POSTGRES_DB=roundelay \
		-p 55432:5432 docker.io/library/postgres:17-alpine
	@until pg_isready -h 127.0.0.1 -p 55432 -q; do sleep 1; done
	@echo "postgres ready on 55432"

pg-down:
	-podman rm -f roundelay-pg

pg-test:
	ROUNDELAY_TEST_DSN='$(PG_DSN)' go test -count=1 ./pgstore/ ./internal/memstore/

fmt:
	gofmt -l -w .

# What CI runs.
check:
	gofmt -l . | tee /dev/stderr | (! read)
	go vet ./...
	go test ./...
	go run ./internal/conformance/cmd/conformance-lint
	@# Both generated artefacts must be what their generator produces. Drift means
	@# someone changed a construction without regenerating, or regenerated without
	@# reviewing.
	@tmp=$$(mktemp -d) && go run ./internal/vectorgen $$tmp >/dev/null && \
		diff -r vectors $$tmp --exclude=README.md && rm -rf $$tmp && \
		echo "vectors are current"
	@tmp=$$(mktemp -d) && go run ./internal/codegen/codesgen docs/reference/refusal-codes.md $$tmp/codes.go >/dev/null && \
		gofmt -w $$tmp/codes.go && diff codes/codes.go $$tmp/codes.go && rm -rf $$tmp && \
		echo "codes are current"
