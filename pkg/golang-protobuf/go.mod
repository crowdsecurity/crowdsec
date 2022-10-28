// Deprecated: Use the "google.golang.org/protobuf" module instead.
module github.com/golang/protobuf

go 1.9

require (
	github.com/google/go-cmp v0.5.5
	google.golang.org/protobuf v1.26.0
)

replace github.com/golang/protobuf => ../

replace github.com/golang/protobuf/protoc-gen-go/descriptor => ../protoc-gen-go/descriptor

replace github.com/golang/protobuf/proto => ../proto

replace github.com/golang/protobuf/jsonpb => ../jsonpb
