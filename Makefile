BINARY := dfir-collector
CMD := ./cmd/dfir-collector
DIST := dist
LOCAL_PROXY ?= http://127.0.0.1:10808

.PHONY: all build test fmt tidy tidy-proxy clean linux

all: fmt test build

build:
	mkdir -p $(DIST)
	go build -o $(DIST)/$(BINARY) $(CMD)

linux:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(DIST)/$(BINARY)-linux-amd64 $(CMD)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(DIST)/$(BINARY)-linux-arm64 $(CMD)
	CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -o $(DIST)/$(BINARY)-linux-386 $(CMD)

test:
	go test ./...

fmt:
	gofmt -w cmd internal

tidy:
	go mod tidy

tidy-proxy:
	HTTPS_PROXY=$(LOCAL_PROXY) HTTP_PROXY=$(LOCAL_PROXY) GOPROXY=https://proxy.golang.org,direct go mod tidy

clean:
	rm -rf $(DIST)
