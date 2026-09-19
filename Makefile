GO ?= go
BUF_VERSION := v1.72.0
BUF := $(GO) run github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
PROTO_BASELINE ?= main

.PHONY: generate proto-lint proto-breaking proto-check test check

generate:
	$(BUF) generate

proto-lint:
	$(BUF) lint

proto-breaking:
	$(BUF) breaking --against '.git#branch=$(PROTO_BASELINE),subdir=api'

# Generate into an isolated directory and compare the exact checked-in outputs.
# This detects both stale generated code and output in the wrong Go package path.
proto-check: proto-lint
	@set -eu; \
	test ! -e v1/controlplane.pb.go; \
	test ! -e v1/controlplane_grpc.pb.go; \
	tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	$(BUF) generate --output "$$tmp"; \
	diff -u api/v1/controlplane.pb.go "$$tmp/api/v1/controlplane.pb.go"; \
	diff -u api/v1/controlplane_grpc.pb.go "$$tmp/api/v1/controlplane_grpc.pb.go"

test:
	$(GO) test ./...

check: proto-check proto-breaking test
