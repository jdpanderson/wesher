export CGO_ENABLED=0

VERSION := $(shell git describe --tags --dirty --always)

GOFLAGS := -ldflags "-X main.version=$(VERSION) -buildid=" -trimpath

GOARCHES := $(shell go env GOARCH)

GOVULNCHECK := go run golang.org/x/vuln/cmd/govulncheck@v1.7.0
GOLANGCI_LINT := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2

build:
	$(foreach GOARCH,$(GOARCHES),GOARCH=$(GOARCH) go build ${GOFLAGS} -o wesher$(if $(filter-out $(GOARCH), $(GOARCHES)),-$(GOARCH));)

release: build
	sha256sum wesher-* | tee wesher.sha256sums

test:
	CGO_ENABLED=1 go test -race ./...

coverage:
	CGO_ENABLED=1 go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

vulncheck:
	$(GOVULNCHECK) ./...

lint:
	$(GOLANGCI_LINT) run ./...

e2e: build
	tests/e2e.sh

clean:
	rm -f wesher wesher-* wesher.sha256sums coverage.out

.PHONY: build release test coverage vulncheck lint e2e clean
