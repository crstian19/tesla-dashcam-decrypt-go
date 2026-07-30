binary := "tesdecrypt"
package := "./cmd/tesdecrypt"
version := `git describe --tags --always --dirty 2>/dev/null || echo dev`

# List the available recipes
default:
    @just --list

# Build the binary
build:
    go build -ldflags "-s -w -X main.version={{version}}" -o {{binary}} {{package}}

# Run the test suite with the race detector
test:
    go test -race ./...

# Run the tests and report coverage
cover:
    go test -race -coverprofile=coverage.out ./...
    go tool cover -func=coverage.out | tail -1

# Lint and vet
lint:
    go vet ./...
    go tool golangci-lint run

# Format the code
fmt:
    go tool golangci-lint fmt

# Scan dependencies for known vulnerabilities
security:
    go tool govulncheck ./...

# Install the pinned dev tooling into go.mod
setup:
    go get -tool github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
    go get -tool golang.org/x/vuln/cmd/govulncheck@latest

# Everything CI runs
ci: lint test security

# Remove build artefacts
clean:
    rm -f {{binary}} coverage.out
