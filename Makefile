export CGO_ENABLED=0

VERSION := $(shell git describe --tags --dirty --always)

GOFLAGS := -ldflags "-X main.version=$(VERSION) -buildid=" -trimpath

GOARCHES := $(shell go env GOARCH)

GOVULNCHECK := go run golang.org/x/vuln/cmd/govulncheck@v1.7.0
GOLANGCI_LINT := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2

build:
	$(foreach GOARCH,$(GOARCHES),GOARCH=$(GOARCH) go build ${GOFLAGS} -o cheesecloth$(if $(filter-out $(GOARCH), $(GOARCHES)),-$(GOARCH)) ./cmd/cheesecloth;)

release: build
	sha256sum cheesecloth-* | tee cheesecloth.sha256sums

test:
	CGO_ENABLED=1 go test -race ./...

coverage:
	CGO_ENABLED=1 go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

# netns-gated tests need CAP_NET_ADMIN; a user namespace is enough
test-privileged:
	CGO_ENABLED=1 unshare -r go test -race ./...

coverage-privileged:
	CGO_ENABLED=1 unshare -r go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

vulncheck:
	$(GOVULNCHECK) ./...

lint:
	$(GOLANGCI_LINT) run ./...

e2e: build
	tests/e2e.sh

clean:
	rm -f cheesecloth cheesecloth-* cheesecloth.sha256sums coverage.out

.PHONY: build release test coverage test-privileged coverage-privileged vulncheck lint e2e clean
