BINARY  := smtprelayd
PKG     := ./cmd/smtprelayd
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath
export CGO_ENABLED = 0

.PHONY: build build-all test lint check selftest sbom dist clean license

build:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

build-all:
	GOOS=linux   GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-linux-amd64      $(PKG)
	GOOS=linux   GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-linux-arm64      $(PKG)
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-windows-amd64.exe $(PKG)

# Fetch the canonical licence text. It is not kept in the repository as a
# hand-copied file: a licence has to be byte-exact to mean anything.
license:
	curl -fsSL -o LICENSE https://www.gnu.org/licenses/gpl-3.0.txt

test:
	go test -race ./...

lint:
	gofmt -l .
	go vet ./...

# Validate a configuration without starting anything. CONFIG=<path> to override.
CONFIG ?= configs/smtprelayd.example.toml
check: build
	./bin/$(BINARY) -config $(CONFIG) check

# Active open relay probe against a running instance.
selftest: build
	./bin/$(BINARY) -config $(CONFIG) selftest

sbom:
	cyclonedx-gomod app -json -licenses -main $(PKG) -output dist/$(BINARY)-$(VERSION).cdx.json .

dist: build-all sbom
	cd bin && sha256sum * > ../dist/SHA256SUMS

clean:
	rm -rf bin dist
