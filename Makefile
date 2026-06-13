# agentguard — developer tasks
# Zero external build dependencies; everything here uses the Go toolchain only.

BINARY      := agentguard
PKG         := github.com/alexverify/agentguard
CMD         := ./cmd/agentguard
BIN_DIR     := bin
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS     := -s -w -X '$(PKG)/internal/buildinfo.Version=$(VERSION)'

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the static binary into ./bin
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD)

.PHONY: dashboard-web
dashboard-web: ## Build the Next.js dashboard and sync its static export into the embed dir
	cd controlplane/web && npm ci && npm run build
	rm -rf internal/dashboard/assets
	mkdir -p internal/dashboard/assets
	cp -R controlplane/web/out/. internal/dashboard/assets/
	@echo "synced dashboard export → internal/dashboard/assets (rebuild the binary to embed)"

.PHONY: run
run: ## Run the CLI (pass args via ARGS="scan ...")
	go run $(CMD) $(ARGS)

.PHONY: test
test: ## Run all tests
	go test ./...

.PHONY: cover
cover: ## Run tests with coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -n 1

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: fmt
fmt: ## Format the codebase
	gofmt -s -w .

.PHONY: fmt-check
fmt-check: ## Fail if code is not gofmt-clean
	@out="$$(gofmt -s -l .)"; if [ -n "$$out" ]; then echo "Not formatted:"; echo "$$out"; exit 1; fi

.PHONY: lint
lint: ## Run golangci-lint if installed (optional)
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed; skipping"

.PHONY: check
check: fmt-check vet test ## Run the full local CI gate

.PHONY: tidy
tidy: ## Tidy go.mod / go.sum
	go mod tidy

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) dist coverage.out
