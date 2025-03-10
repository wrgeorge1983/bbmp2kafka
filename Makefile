#!/usr/bin/make

build:
	go build

proto-go:
	go mod vendor
	protoc \
		-Ivendor/github.com/bio-routing/bio-rd \
		--go_out=protos \
		--go_opt=paths=source_relative \
		--proto_path=protos \
		protos/bbmp/bbmp.proto
	rm -rf vendor
