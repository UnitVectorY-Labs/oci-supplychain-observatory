
# Commands for oci-supplychain-observatory
default:
  @just --list
# Build oci-supplychain-observatory with Go
build:
  go build ./...

# Run tests for oci-supplychain-observatory with Go
test:
  go clean -testcache
  go test ./...