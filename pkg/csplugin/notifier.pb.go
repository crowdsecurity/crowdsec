// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.12.4
// source: notifier.proto

package csplugin

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Notification struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Text string `protobuf:"bytes,1,opt,name=text,proto3" json:"text,omitempty"`
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *Notification) Reset() {
	*x = Notification{}
	if protoimpl.UnsafeEnabled {
		mi := &file_notifier_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Notification) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Notification) ProtoMessage() {}

func (x *Notification) ProtoReflect() protoreflect.Message {
	mi := &file_notifier_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Notification.ProtoReflect.Descriptor instead.
func (*Notification) Descriptor() ([]byte, []int) {
	return file_notifier_proto_rawDescGZIP(), []int{0}
}

func (x *Notification) GetText() string {
	if x != nil {
		return x.Text
	}
	return ""
}

func (x *Notification) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Config []byte `protobuf:"bytes,2,opt,name=config,proto3" json:"config,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_notifier_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_notifier_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Config.ProtoReflect.Descriptor instead.
func (*Config) Descriptor() ([]byte, []int) {
	return file_notifier_proto_rawDescGZIP(), []int{1}
}

func (x *Config) GetConfig() []byte {
	if x != nil {
		return x.Config
	}
	return nil
}

type Empty struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Empty) Reset() {
	*x = Empty{}
	if protoimpl.UnsafeEnabled {
		mi := &file_notifier_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Empty) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Empty) ProtoMessage() {}

func (x *Empty) ProtoReflect() protoreflect.Message {
	mi := &file_notifier_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Empty.ProtoReflect.Descriptor instead.
func (*Empty) Descriptor() ([]byte, []int) {
	return file_notifier_proto_rawDescGZIP(), []int{2}
}

var File_notifier_proto protoreflect.FileDescriptor

var file_notifier_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x36, 0x0a, 0x0c, 0x4e, 0x6f, 0x74, 0x69, 0x66,
	0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x65, 0x78, 0x74, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x65, 0x78, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22,
	0x20, 0x0a, 0x06, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x16, 0x0a, 0x06, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x22, 0x07, 0x0a, 0x05, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x32, 0x61, 0x0a, 0x08, 0x4e, 0x6f,
	0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x12, 0x2b, 0x0a, 0x06, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79,
	0x12, 0x13, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x1a, 0x0c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x45, 0x6d,
	0x70, 0x74, 0x79, 0x12, 0x28, 0x0a, 0x09, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x65,
	0x12, 0x0d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x1a,
	0x0c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x42, 0x0c, 0x5a,
	0x0a, 0x2e, 0x3b, 0x63, 0x73, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_notifier_proto_rawDescOnce sync.Once
	file_notifier_proto_rawDescData = file_notifier_proto_rawDesc
)

func file_notifier_proto_rawDescGZIP() []byte {
	file_notifier_proto_rawDescOnce.Do(func() {
		file_notifier_proto_rawDescData = protoimpl.X.CompressGZIP(file_notifier_proto_rawDescData)
	})
	return file_notifier_proto_rawDescData
}

var file_notifier_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_notifier_proto_goTypes = []interface{}{
	(*Notification)(nil), // 0: proto.Notification
	(*Config)(nil),       // 1: proto.Config
	(*Empty)(nil),        // 2: proto.Empty
}
var file_notifier_proto_depIdxs = []int32{
	0, // 0: proto.Notifier.Notify:input_type -> proto.Notification
	1, // 1: proto.Notifier.Configure:input_type -> proto.Config
	2, // 2: proto.Notifier.Notify:output_type -> proto.Empty
	2, // 3: proto.Notifier.Configure:output_type -> proto.Empty
	2, // [2:4] is the sub-list for method output_type
	0, // [0:2] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_notifier_proto_init() }
func file_notifier_proto_init() {
	if File_notifier_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_notifier_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Notification); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_notifier_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Config); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_notifier_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Empty); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_notifier_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_notifier_proto_goTypes,
		DependencyIndexes: file_notifier_proto_depIdxs,
		MessageInfos:      file_notifier_proto_msgTypes,
	}.Build()
	File_notifier_proto = out.File
	file_notifier_proto_rawDesc = nil
	file_notifier_proto_goTypes = nil
	file_notifier_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// NotifierClient is the client API for Notifier service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type NotifierClient interface {
	Notify(ctx context.Context, in *Notification, opts ...grpc.CallOption) (*Empty, error)
	Configure(ctx context.Context, in *Config, opts ...grpc.CallOption) (*Empty, error)
}

type notifierClient struct {
	cc grpc.ClientConnInterface
}

func NewNotifierClient(cc grpc.ClientConnInterface) NotifierClient {
	return &notifierClient{cc}
}

func (c *notifierClient) Notify(ctx context.Context, in *Notification, opts ...grpc.CallOption) (*Empty, error) {
	out := new(Empty)
	err := c.cc.Invoke(ctx, "/proto.Notifier/Notify", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *notifierClient) Configure(ctx context.Context, in *Config, opts ...grpc.CallOption) (*Empty, error) {
	out := new(Empty)
	err := c.cc.Invoke(ctx, "/proto.Notifier/Configure", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// NotifierServer is the server API for Notifier service.
type NotifierServer interface {
	Notify(context.Context, *Notification) (*Empty, error)
	Configure(context.Context, *Config) (*Empty, error)
}

// UnimplementedNotifierServer can be embedded to have forward compatible implementations.
type UnimplementedNotifierServer struct {
}

func (*UnimplementedNotifierServer) Notify(context.Context, *Notification) (*Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Notify not implemented")
}
func (*UnimplementedNotifierServer) Configure(context.Context, *Config) (*Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Configure not implemented")
}

func RegisterNotifierServer(s *grpc.Server, srv NotifierServer) {
	s.RegisterService(&_Notifier_serviceDesc, srv)
}

func _Notifier_Notify_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Notification)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NotifierServer).Notify(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.Notifier/Notify",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NotifierServer).Notify(ctx, req.(*Notification))
	}
	return interceptor(ctx, in, info, handler)
}

func _Notifier_Configure_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Config)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NotifierServer).Configure(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.Notifier/Configure",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NotifierServer).Configure(ctx, req.(*Config))
	}
	return interceptor(ctx, in, info, handler)
}

var _Notifier_serviceDesc = grpc.ServiceDesc{
	ServiceName: "proto.Notifier",
	HandlerType: (*NotifierServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Notify",
			Handler:    _Notifier_Notify_Handler,
		},
		{
			MethodName: "Configure",
			Handler:    _Notifier_Configure_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "notifier.proto",
}
