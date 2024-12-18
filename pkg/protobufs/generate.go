package protobufs

// Dependencies:
//
// apt install protobuf-compiler
//
// keep this in sync with go.mod
// go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.2
//
// Not the same versions as google.golang.org/grpc
// go list -m -versions google.golang.org/grpc/cmd/protoc-gen-go-grpc
// go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative notifier.proto
