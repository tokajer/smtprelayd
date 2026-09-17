BINARY  := smtprelayd
PKG     := ./cmd/smtprelayd
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath
export CGO_ENABLED = 0

.PHONY: build build-all test lint check selftest selftest-ci sbom dist dist-dir clean license

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

# CGO_ENABLED=1 for this target only. The race detector needs cgo at test
# build time; the shipped binary is still pure Go, which is what the
# CGO_ENABLED=0 above and the build targets below enforce. Without the
# override this target fails before running a single test, which is what it
# did until 2026-09-17 while CI passed -- CI calls go test directly and never
# sees this file.
test: export CGO_ENABLED = 1
test:
	go test -race ./...

lint:
	gofmt -l .
	go vet ./...
	./scripts/check-banned-imports.sh

# Validate a configuration without starting anything. CONFIG=<path> to override.
CONFIG ?= configs/smtprelayd.example.toml
check: build
	./bin/$(BINARY) -config $(CONFIG) check

# Active open relay probe against an instance you are already running.
selftest: build
	./bin/$(BINARY) -config $(CONFIG) selftest

# The same probe, but it starts and stops its own throwaway instance, so it
# needs nothing running. This is what CI gates on.
selftest-ci: build
	./scripts/selftest-ci.sh

sbom: | dist-dir
	cyclonedx-gomod app -json -licenses -main $(PKG) -output dist/$(BINARY)-$(VERSION).cdx.json .

dist-dir:
	mkdir -p dist

dist: build-all sbom
	cd bin && sha256sum * > ../dist/SHA256SUMS

clean:
	rm -rf bin dist
