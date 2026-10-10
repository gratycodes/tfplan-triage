.PHONY: build test lint golden fixtures

build:
	go build -o tfplan-triage ./cmd/tfplan-triage

test:
	go vet ./...
	go test -race ./...

lint:
	golangci-lint run ./...

# Rewrite report golden files; review the diff before committing.
golden:
	go test ./internal/report -update

# Regenerate testdata/plans with terraform and tofu (no cloud credentials).
fixtures:
	./testdata/src/gen.sh
