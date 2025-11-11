.PHONY: build run clean install test fmt vet deps generate-config docker-build docker-run

# Binary name
BINARY_NAME=breadcrumb-pot
DOCKER_IMAGE=breadcrumb-pot:latest

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@go build -o $(BINARY_NAME) cmd/breadcrumb-pot/main.go
	@echo "Build complete: ./$(BINARY_NAME)"

# Build for multiple platforms
build-all:
	@echo "Building for multiple platforms..."
	@GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)-linux-amd64 cmd/breadcrumb-pot/main.go
	@GOOS=darwin GOARCH=amd64 go build -o $(BINARY_NAME)-darwin-amd64 cmd/breadcrumb-pot/main.go
	@GOOS=windows GOARCH=amd64 go build -o $(BINARY_NAME)-windows-amd64.exe cmd/breadcrumb-pot/main.go
	@echo "Multi-platform build complete"

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

# Run the honeypot
run: build
	@echo "Running $(BINARY_NAME)..."
	@./$(BINARY_NAME) -config config.yaml

# Run with sudo for privileged ports
run-sudo: build
	@echo "Running $(BINARY_NAME) with sudo..."
	@sudo ./$(BINARY_NAME) -config config.yaml

# Generate default configuration
generate-config: build
	@echo "Generating default configuration..."
	@./$(BINARY_NAME) -generate-config
	@echo "Configuration generated: config.yaml"

# Install the binary to /usr/local/bin
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	@sudo cp $(BINARY_NAME) /usr/local/bin/
	@echo "Installed successfully"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -f $(BINARY_NAME)
	@rm -f $(BINARY_NAME)-*
	@rm -rf logs/
	@echo "Clean complete"

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Run go vet
vet:
	@echo "Running go vet..."
	@go vet ./...

# Run linter (requires golangci-lint)
lint:
	@echo "Running linter..."
	@golangci-lint run

# Create necessary directories
setup:
	@echo "Setting up directories..."
	@mkdir -p templates logs
	@echo "Setup complete"

# Download official Nuclei templates
setup-nuclei:
	@echo "Setting up Nuclei templates..."
	@./scripts/setup-templates.sh
	@echo "Update config.yaml to use: nuclei-templates/http"

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	@docker build -t $(DOCKER_IMAGE) .
	@echo "Docker image built: $(DOCKER_IMAGE)"

# Run Docker container
docker-run:
	@echo "Running Docker container..."
	@docker run -p 8080:8080 -p 53:53/udp -v $(PWD)/templates:/app/templates -v $(PWD)/logs:/app/logs $(DOCKER_IMAGE)

# Help
help:
	@echo "Available targets:"
	@echo "  build           - Build the binary"
	@echo "  build-all       - Build for multiple platforms"
	@echo "  deps            - Install dependencies"
	@echo "  run             - Build and run the honeypot"
	@echo "  run-sudo        - Build and run with sudo (for privileged ports)"
	@echo "  generate-config - Generate default config.yaml"
	@echo "  install         - Install binary to /usr/local/bin"
	@echo "  clean           - Remove build artifacts"
	@echo "  test            - Run tests"
	@echo "  test-coverage   - Run tests with coverage report"
	@echo "  fmt             - Format code"
	@echo "  vet             - Run go vet"
	@echo "  lint            - Run linter"
	@echo "  setup           - Create necessary directories"
	@echo "  setup-nuclei    - Download official Nuclei templates"
	@echo "  docker-build    - Build Docker image"
	@echo "  docker-run      - Run Docker container"
	@echo "  help            - Show this help message"

# Default target
.DEFAULT_GOAL := help
