#!/bin/bash

# Update packages
#go get -u ./... && go mod tidy

echo "Run gofmt"
gofmt -w *.go internal/*/*.go

echo "Run test with cover"
go test ./... -cover

echo "Run race test"
go test ./... -race -timeout 120s
