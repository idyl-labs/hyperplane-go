# Copyright 2026 Idyl Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Every target runs against this module alone, ignoring any go.work file
# above it, so that what passes here is what a consumer of the module gets.
export GOWORK := off

# Tool versions are pinned so that local runs and CI agree. Bump a version in
# its own change so that any new findings are reviewed on their own.
GOLANGCI_LINT := github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
GOVULNCHECK   := golang.org/x/vuln/cmd/govulncheck@v1.8.0
ADDLICENSE    := github.com/google/addlicense@v1.2.0
BUF           := github.com/bufbuild/buf/cmd/buf@v1.70.0
PROTOC_GEN_GO := google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11

.DEFAULT_GOAL := help

.PHONY: help
help:
	@printf '%s\n' \
		'Targets:' \
		'  check          tidy-check, deps-check, license-check, lint, proto-check, test, vuln' \
		'  test           tests with the race detector' \
		'  cover          test coverage' \
		'  lint           golangci-lint' \
		'  fmt            format code and imports' \
		'  tidy-check     verify go.mod and go.sum are tidy' \
		'  deps-check     verify no other module of this organisation is required' \
		'  license-check  verify license headers' \
		'  vuln           govulncheck' \
		'  proto          regenerate protobuf code' \
		'  proto-check    lint protos and verify generated code is current' \
		'  breaking       protocol changes that break compatibility with main'

.PHONY: check
check: tidy-check deps-check license-check lint proto-check test vuln

.PHONY: test
test:
	go test -race ./...

.PHONY: cover
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

.PHONY: lint
lint:
	go run $(GOLANGCI_LINT) run ./...

.PHONY: fmt
fmt:
	go run $(GOLANGCI_LINT) fmt ./...

.PHONY: tidy-check
tidy-check:
	go mod tidy -diff

# The module stands alone: no other module published under its organisation
# may appear anywhere in its module graph, tests and tools included.
.PHONY: deps-check
deps-check:
	@set -eu; self="$$(go list -m)"; org="$${self%/*}/"; \
	modules="$$(go list -m -f '{{.Path}}' all)"; \
	others="$$(printf '%s\n' "$$modules" | grep -F "$$org" | grep -vxF "$$self" || true)"; \
	if [ -n "$$others" ]; then echo "module graph requires:"; echo "$$others"; exit 1; fi

.PHONY: license-check
license-check:
	git ls-files -z | xargs -0 go run $(ADDLICENSE) -check -f .license-header

.PHONY: vuln
vuln:
	go run $(GOVULNCHECK) ./...

# The protocol definitions live under wire/proto; the generated packages are
# written beside the hand-written code under wire.
.PHONY: proto
proto:
	GOBIN=$(CURDIR)/.bin go install $(PROTOC_GEN_GO)
	cd wire && PATH=$(CURDIR)/.bin:$$PATH go run $(BUF) generate

.PHONY: proto-check
proto-check: proto
	cd wire && go run $(BUF) lint
	@changes="$$(git status --porcelain -- wire)"; if [ -n "$$changes" ]; then \
		echo "generated code is not current:"; echo "$$changes"; exit 1; fi

.PHONY: breaking
breaking:
	go run $(BUF) breaking wire --against '.git#branch=main,subdir=wire'
