#!/bin/sh
set -eu
cd "$(dirname "$0")"
go test -race ./...
go vet ./...
mkdir -p ../webroot/common_scripts/bin
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o ../webroot/common_scripts/bin/box-autopilot .
