
BINARY     := kitinspect
VERSION    := 1.0.0
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
PKG        := github.com/kitinspect/kitinspect
LDFLAGS    := -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)
GO_FILES   := $(shell find . -name '*.go' -not -path './vendor/*')
CYAN  := \033[0;36m
GREEN := \033[0;32m
RESET := \033[0m

.PHONY: all build clean install test lint tidy run-help docker
all: build
build:
	@printf "$(CYAN)Building KitInspect v$(VERSION)...$(RESET)\n"
	@go build -ldflags "$(LDFLAGS)" -trimpath -o $(BINARY) ./cmd/kitinspect/
	@printf "$(GREEN)✔ Built: ./$(BINARY)$(RESET)\n"
build-linux:
	@printf "$(CYAN)Building for linux/amd64...$(RESET)\n"
	@GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -trimpath -o dist/$(BINARY)-linux-amd64 ./cmd/kitinspect/
	@printf "$(GREEN)✔ dist/$(BINARY)-linux-amd64$(RESET)\n"
build-macos:
	@printf "$(CYAN)Building for darwin/arm64...$(RESET)\n"
	@GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -trimpath -o dist/$(BINARY)-darwin-arm64 ./cmd/kitinspect/
	@printf "$(GREEN)✔ dist/$(BINARY)-darwin-arm64$(RESET)\n"
build-windows:
	@printf "$(CYAN)Building for windows/amd64...$(RESET)\n"
	@GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -trimpath -o dist/$(BINARY)-windows-amd64.exe ./cmd/kitinspect/
	@printf "$(GREEN)✔ dist/$(BINARY)-windows-amd64.exe$(RESET)\n"
build-all: build-linux build-macos build-windows
install: build
	@printf "$(CYAN)Installing to /usr/local/bin/$(BINARY)...$(RESET)\n"
	@install -m 755 $(BINARY) /usr/local/bin/$(BINARY)
	@printf "$(GREEN)✔ Installed$(RESET)\n"
test:
	@printf "$(CYAN)Running tests...$(RESET)\n"
	@go test -v -race ./...
test-coverage:
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@printf "$(GREEN)✔ Coverage report: coverage.html$(RESET)\n"
lint:
	@which golangci-lint > /dev/null 2>&1 || (printf "Installing golangci-lint...\n" && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	@golangci-lint run ./...
tidy:
	@go mod tidy
	@printf "$(GREEN)✔ Modules tidied$(RESET)\n"
clean:
	@rm -f $(BINARY) coverage.out coverage.html
	@rm -rf dist/
	@printf "$(GREEN)✔ Cleaned$(RESET)\n"
docker:
	@printf "$(CYAN)Building Docker image...$(RESET)\n"
	@docker build -t kitinspect:$(VERSION) -t kitinspect:latest .
	@printf "$(GREEN)✔ Image: kitinspect:$(VERSION)$(RESET)\n"
run-help: build
	@./$(BINARY) --help
version: build
	@./$(BINARY) version
help:
	@printf "\n  KitInspect Build System\n\n"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /' | column -t -s ':'
	@printf "\n"
