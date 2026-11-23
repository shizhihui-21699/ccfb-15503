.PHONY: all build test race selftest attackcheck vet fmt linux clean

all: build

build:
	go build ./...

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

selftest:
	go run ./cmd/powfence-selftest -windows 250

attackcheck:
	go run ./cmd/powfence-attackcheck

# Production binaries target Linux hosts even when built on macOS.
linux:
	GOOS=linux GOARCH=amd64 go build ./...

clean:
	rm -rf bin/
