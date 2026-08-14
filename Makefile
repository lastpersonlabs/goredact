.PHONY: bin build test lint fuzz-smoke bench bench-large bench-ci accuracy-secretbench cover

FUZZTIME ?= 10s

# Compile all packages.
build:
	go build ./...

bin:
	go build -o ./bin ./... 

# Run the full test suite with the race detector enabled.
test:
	go test -race ./...

# gofmt + go vet + staticcheck. The module itself stays dependency-free;
# staticcheck is fetched on the fly via `go run` and is not a module
# dependency.
lint:
	@fmt_out="$$(gofmt -l .)"; \
	if [ -n "$$fmt_out" ]; then \
		echo "The following files are not gofmt-formatted:" >&2; \
		echo "$$fmt_out" >&2; \
		echo "Run 'gofmt -w .' and commit the result." >&2; \
		exit 1; \
	fi
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

# Discover every FuzzXxx target across all packages and run each for
# FUZZTIME (default 10s). Tolerates packages with no fuzz targets.
fuzz-smoke:
	@set -euo pipefail; \
	found_any=0; \
	for pkg in $$(go list ./...); do \
		targets="$$(go test -list '^Fuzz[A-Za-z0-9_]*$$' "$$pkg" 2>/dev/null | grep -E '^Fuzz[A-Za-z0-9_]*$$' || true)"; \
		if [ -z "$$targets" ]; then \
			continue; \
		fi; \
		while IFS= read -r target; do \
			[ -z "$$target" ] && continue; \
			found_any=1; \
			echo "Fuzzing $$target ($$pkg) for $(FUZZTIME)"; \
			go test -run '^$$' -fuzz "^$${target}$$" -fuzztime $(FUZZTIME) "$$pkg"; \
		done <<< "$$targets"; \
	done; \
	if [ "$$found_any" -eq 0 ]; then \
		echo "No fuzz targets found in any package; nothing to run."; \
	fi

# Run every benchmark once (no meaningful timing).
bench:
	go test -run '^$$' -bench . -benchtime 1x ./...

# Full generated 100 MiB/500 MiB/1 GiB benchmark matrix. Override ARGS to
# select a subset, for example ARGS='-profiles fast -output fast.json'.
bench-large:
	go run ./tools/benchreport $(ARGS)

# Small, stable performance budget suitable for shared CI runners.
bench-ci:
	go run ./tools/benchreport -sizes 16MiB -scenarios adversarial,confirmed-secret \
		-profiles balanced -modes raw -min-throughput 5 -max-alloc-per-byte 0.25 \
		-output benchmark-ci.json

# Evaluate a locally acquired SecretBench corpus. Pass paths and coordinate
# options through ARGS; the access-controlled dataset is never downloaded.
accuracy-secretbench:
	go run ./tools/secretbench $(ARGS)

# Generate and summarize test coverage.
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
