#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

# gometalinter

if [ ! $(command -v gometalinter) ]
then
	go get github.com/alecthomas/gometalinter
	gometalinter --update --install
fi

echo "gometalinter:"
time gometalinter \
	--exclude='/thrift/' \
	--exclude='/pb/' \
	--exclude='no args in Log call \(vet\)' \
	--disable=errcheck \
	--disable=dupl \
	--disable=aligncheck \
	--disable=gotype \
	--cyclo-over=20 \
	--tests \
	--concurrency=2 \
	--deadline=300s \
	./...
echo 

# golangci-lint

if [ ! $(command -v golangci-lint) ]
then
	go get github.com/golangci/golangci-lint/cmd/golangci-lint
fi


echo "golangci-lint:"
time golangci-lint \
	run \
	--disable errcheck \
	./... 