.PHONY: all test vectors codes generate check fmt

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

test:
	go test ./...

fmt:
	gofmt -l -w .

# What CI runs.
check:
	gofmt -l . | tee /dev/stderr | (! read)
	go vet ./...
	go test ./...
	@# Both generated artefacts must be what their generator produces. Drift means
	@# someone changed a construction without regenerating, or regenerated without
	@# reviewing.
	@tmp=$$(mktemp -d) && go run ./internal/vectorgen $$tmp >/dev/null && \
		diff -r vectors $$tmp --exclude=README.md && rm -rf $$tmp && \
		echo "vectors are current"
	@tmp=$$(mktemp -d) && go run ./internal/codegen/codesgen docs/reference/refusal-codes.md $$tmp/codes.go >/dev/null && \
		gofmt -w $$tmp/codes.go && diff codes/codes.go $$tmp/codes.go && rm -rf $$tmp && \
		echo "codes are current"
