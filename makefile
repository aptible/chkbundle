SHELL=/bin/bash
GOFMT_FILES?=$$(find . -name '*.go' |grep -v vendor)

.PHONY: build
build:
	go build

.PHONY: test
test:
	go test $$(go list ./... | grep -v /vendor/)
	go vet $$(go list ./... | grep -v /vendor/)

.PHONY: fmt
fmt:
	gofmt -l -w ${GOFMT_FILES}

.DEFAULT_GOAL := test
