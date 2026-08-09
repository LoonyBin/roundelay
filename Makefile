.PHONY: all test vectors check fmt

all: check

# Regenerate the frozen vectors. A diff here is a change to the
# cross-implementation contract — review it as one.
vectors:
	go run ./internal/vectorgen ./vectors

test:
	go test ./...

fmt:
	gofmt -l -w .

# What CI runs.
check:
	gofmt -l . | tee /dev/stderr | (! read)
	go vet ./...
	go test ./...
	@# The vectors on disk must be what the generator produces. A drift here means
	@# someone changed a construction without regenerating, or regenerated without
	@# reviewing.
	@tmp=$$(mktemp -d) && go run ./internal/vectorgen $$tmp >/dev/null && \
		diff -r vectors $$tmp --exclude=README.md && rm -rf $$tmp && \
		echo "vectors are current"
