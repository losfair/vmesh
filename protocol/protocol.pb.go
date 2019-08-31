// Code generated by protoc-gen-go. DO NOT EDIT.
// source: protocol/protocol.proto

package protocol

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Message struct {
	Tag                  uint32   `protobuf:"varint,1,opt,name=tag,proto3" json:"tag,omitempty"`
	Payload              []byte   `protobuf:"bytes,2,opt,name=payload,proto3" json:"payload,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Message) Reset()         { *m = Message{} }
func (m *Message) String() string { return proto.CompactTextString(m) }
func (*Message) ProtoMessage()    {}
func (*Message) Descriptor() ([]byte, []int) {
	return fileDescriptor_87968d26f3046c60, []int{0}
}

func (m *Message) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Message.Unmarshal(m, b)
}
func (m *Message) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Message.Marshal(b, m, deterministic)
}
func (m *Message) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Message.Merge(m, src)
}
func (m *Message) XXX_Size() int {
	return xxx_messageInfo_Message.Size(m)
}
func (m *Message) XXX_DiscardUnknown() {
	xxx_messageInfo_Message.DiscardUnknown(m)
}

var xxx_messageInfo_Message proto.InternalMessageInfo

func (m *Message) GetTag() uint32 {
	if m != nil {
		return m.Tag
	}
	return 0
}

func (m *Message) GetPayload() []byte {
	if m != nil {
		return m.Payload
	}
	return nil
}

type Announcement struct {
	Routes               []*Route `protobuf:"bytes,1,rep,name=routes,proto3" json:"routes,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Announcement) Reset()         { *m = Announcement{} }
func (m *Announcement) String() string { return proto.CompactTextString(m) }
func (*Announcement) ProtoMessage()    {}
func (*Announcement) Descriptor() ([]byte, []int) {
	return fileDescriptor_87968d26f3046c60, []int{1}
}

func (m *Announcement) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Announcement.Unmarshal(m, b)
}
func (m *Announcement) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Announcement.Marshal(b, m, deterministic)
}
func (m *Announcement) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Announcement.Merge(m, src)
}
func (m *Announcement) XXX_Size() int {
	return xxx_messageInfo_Announcement.Size(m)
}
func (m *Announcement) XXX_DiscardUnknown() {
	xxx_messageInfo_Announcement.DiscardUnknown(m)
}

var xxx_messageInfo_Announcement proto.InternalMessageInfo

func (m *Announcement) GetRoutes() []*Route {
	if m != nil {
		return m.Routes
	}
	return nil
}

type Route struct {
	Prefix               []byte   `protobuf:"bytes,1,opt,name=prefix,proto3" json:"prefix,omitempty"`
	PrefixLength         uint32   `protobuf:"varint,2,opt,name=prefix_length,json=prefixLength,proto3" json:"prefix_length,omitempty"`
	Path                 []*Hop   `protobuf:"bytes,3,rep,name=path,proto3" json:"path,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Route) Reset()         { *m = Route{} }
func (m *Route) String() string { return proto.CompactTextString(m) }
func (*Route) ProtoMessage()    {}
func (*Route) Descriptor() ([]byte, []int) {
	return fileDescriptor_87968d26f3046c60, []int{2}
}

func (m *Route) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Route.Unmarshal(m, b)
}
func (m *Route) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Route.Marshal(b, m, deterministic)
}
func (m *Route) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Route.Merge(m, src)
}
func (m *Route) XXX_Size() int {
	return xxx_messageInfo_Route.Size(m)
}
func (m *Route) XXX_DiscardUnknown() {
	xxx_messageInfo_Route.DiscardUnknown(m)
}

var xxx_messageInfo_Route proto.InternalMessageInfo

func (m *Route) GetPrefix() []byte {
	if m != nil {
		return m.Prefix
	}
	return nil
}

func (m *Route) GetPrefixLength() uint32 {
	if m != nil {
		return m.PrefixLength
	}
	return 0
}

func (m *Route) GetPath() []*Hop {
	if m != nil {
		return m.Path
	}
	return nil
}

type Hop struct {
	Id                   []byte   `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Latency              uint32   `protobuf:"varint,2,opt,name=latency,proto3" json:"latency,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Hop) Reset()         { *m = Hop{} }
func (m *Hop) String() string { return proto.CompactTextString(m) }
func (*Hop) ProtoMessage()    {}
func (*Hop) Descriptor() ([]byte, []int) {
	return fileDescriptor_87968d26f3046c60, []int{3}
}

func (m *Hop) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Hop.Unmarshal(m, b)
}
func (m *Hop) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Hop.Marshal(b, m, deterministic)
}
func (m *Hop) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Hop.Merge(m, src)
}
func (m *Hop) XXX_Size() int {
	return xxx_messageInfo_Hop.Size(m)
}
func (m *Hop) XXX_DiscardUnknown() {
	xxx_messageInfo_Hop.DiscardUnknown(m)
}

var xxx_messageInfo_Hop proto.InternalMessageInfo

func (m *Hop) GetId() []byte {
	if m != nil {
		return m.Id
	}
	return nil
}

func (m *Hop) GetLatency() uint32 {
	if m != nil {
		return m.Latency
	}
	return 0
}

type DistributedConfig struct {
	Version              uint32   `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	Certificate          []byte   `protobuf:"bytes,2,opt,name=certificate,proto3" json:"certificate,omitempty"`
	Content              []byte   `protobuf:"bytes,3,opt,name=content,proto3" json:"content,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DistributedConfig) Reset()         { *m = DistributedConfig{} }
func (m *DistributedConfig) String() string { return proto.CompactTextString(m) }
func (*DistributedConfig) ProtoMessage()    {}
func (*DistributedConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_87968d26f3046c60, []int{4}
}

func (m *DistributedConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DistributedConfig.Unmarshal(m, b)
}
func (m *DistributedConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DistributedConfig.Marshal(b, m, deterministic)
}
func (m *DistributedConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DistributedConfig.Merge(m, src)
}
func (m *DistributedConfig) XXX_Size() int {
	return xxx_messageInfo_DistributedConfig.Size(m)
}
func (m *DistributedConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_DistributedConfig.DiscardUnknown(m)
}

var xxx_messageInfo_DistributedConfig proto.InternalMessageInfo

func (m *DistributedConfig) GetVersion() uint32 {
	if m != nil {
		return m.Version
	}
	return 0
}

func (m *DistributedConfig) GetCertificate() []byte {
	if m != nil {
		return m.Certificate
	}
	return nil
}

func (m *DistributedConfig) GetContent() []byte {
	if m != nil {
		return m.Content
	}
	return nil
}

func init() {
	proto.RegisterType((*Message)(nil), "Message")
	proto.RegisterType((*Announcement)(nil), "Announcement")
	proto.RegisterType((*Route)(nil), "Route")
	proto.RegisterType((*Hop)(nil), "Hop")
	proto.RegisterType((*DistributedConfig)(nil), "DistributedConfig")
}

func init() { proto.RegisterFile("protocol/protocol.proto", fileDescriptor_87968d26f3046c60) }

var fileDescriptor_87968d26f3046c60 = []byte{
	// 303 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x4c, 0x91, 0xc1, 0x4e, 0xe3, 0x30,
	0x10, 0x86, 0x37, 0x4d, 0x9b, 0x56, 0xd3, 0x74, 0xb5, 0xeb, 0x03, 0x58, 0x1c, 0x50, 0x08, 0x97,
	0x5c, 0x48, 0x51, 0x11, 0x0f, 0x80, 0xe0, 0x50, 0x24, 0x90, 0x90, 0x0f, 0x1c, 0x41, 0x6e, 0x32,
	0x6d, 0x2d, 0x05, 0xdb, 0x72, 0x26, 0x88, 0xbe, 0x3d, 0x8a, 0xeb, 0x20, 0x6e, 0xff, 0xf7, 0x49,
	0x9e, 0xd1, 0xfc, 0x86, 0x53, 0xeb, 0x0c, 0x99, 0xca, 0x34, 0xcb, 0x21, 0x94, 0x3e, 0xe4, 0xb7,
	0x30, 0x7d, 0xc6, 0xb6, 0x95, 0x3b, 0x64, 0xff, 0x20, 0x26, 0xb9, 0xe3, 0x51, 0x16, 0x15, 0x0b,
	0xd1, 0x47, 0xc6, 0x61, 0x6a, 0xe5, 0xa1, 0x31, 0xb2, 0xe6, 0xa3, 0x2c, 0x2a, 0x52, 0x31, 0x60,
	0x5e, 0x42, 0x7a, 0xa7, 0xb5, 0xe9, 0x74, 0x85, 0x1f, 0xa8, 0x89, 0x9d, 0x43, 0xe2, 0x4c, 0x47,
	0xd8, 0xf2, 0x28, 0x8b, 0x8b, 0xf9, 0x2a, 0x29, 0x45, 0x8f, 0x22, 0xd8, 0xfc, 0x0d, 0x26, 0x5e,
	0xb0, 0x13, 0x48, 0xac, 0xc3, 0xad, 0xfa, 0xf2, 0x7b, 0x52, 0x11, 0x88, 0x5d, 0xc2, 0xe2, 0x98,
	0xde, 0x1b, 0xd4, 0x3b, 0xda, 0xfb, 0x85, 0x0b, 0x91, 0x1e, 0xe5, 0x93, 0x77, 0x8c, 0xc3, 0xd8,
	0x4a, 0xda, 0xf3, 0xd8, 0xef, 0x18, 0x97, 0x6b, 0x63, 0x85, 0x37, 0xf9, 0x12, 0xe2, 0xb5, 0xb1,
	0xec, 0x2f, 0x8c, 0x54, 0x1d, 0x26, 0x8f, 0x54, 0xdd, 0x1f, 0xd0, 0x48, 0x42, 0x5d, 0x1d, 0xc2,
	0xbc, 0x01, 0x73, 0x05, 0xff, 0x1f, 0x54, 0x4b, 0x4e, 0x6d, 0x3a, 0xc2, 0xfa, 0xde, 0xe8, 0xad,
	0xf2, 0xf7, 0x7e, 0xa2, 0x6b, 0x95, 0xd1, 0xa1, 0x85, 0x01, 0x59, 0x06, 0xf3, 0x0a, 0x1d, 0xa9,
	0xad, 0xaa, 0x24, 0x61, 0x68, 0xe3, 0xb7, 0xea, 0xdf, 0x56, 0x46, 0x13, 0x6a, 0xe2, 0xf1, 0xb1,
	0xab, 0x80, 0xab, 0x2b, 0x98, 0xbd, 0x6a, 0xa4, 0x17, 0x44, 0xc7, 0x2e, 0x60, 0xf2, 0xa8, 0x6d,
	0x47, 0x6c, 0x56, 0x86, 0xda, 0xcf, 0x7e, 0x52, 0xfe, 0xa7, 0x88, 0xae, 0xa3, 0x4d, 0xe2, 0x3f,
	0xe6, 0xe6, 0x3b, 0x00, 0x00, 0xff, 0xff, 0xeb, 0xfa, 0x6e, 0xb1, 0xb3, 0x01, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// VnetPeerClient is the client API for VnetPeer service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type VnetPeerClient interface {
	Input(ctx context.Context, opts ...grpc.CallOption) (VnetPeer_InputClient, error)
}

type vnetPeerClient struct {
	cc *grpc.ClientConn
}

func NewVnetPeerClient(cc *grpc.ClientConn) VnetPeerClient {
	return &vnetPeerClient{cc}
}

func (c *vnetPeerClient) Input(ctx context.Context, opts ...grpc.CallOption) (VnetPeer_InputClient, error) {
	stream, err := c.cc.NewStream(ctx, &_VnetPeer_serviceDesc.Streams[0], "/VnetPeer/Input", opts...)
	if err != nil {
		return nil, err
	}
	x := &vnetPeerInputClient{stream}
	return x, nil
}

type VnetPeer_InputClient interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ClientStream
}

type vnetPeerInputClient struct {
	grpc.ClientStream
}

func (x *vnetPeerInputClient) Send(m *Message) error {
	return x.ClientStream.SendMsg(m)
}

func (x *vnetPeerInputClient) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// VnetPeerServer is the server API for VnetPeer service.
type VnetPeerServer interface {
	Input(VnetPeer_InputServer) error
}

func RegisterVnetPeerServer(s *grpc.Server, srv VnetPeerServer) {
	s.RegisterService(&_VnetPeer_serviceDesc, srv)
}

func _VnetPeer_Input_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(VnetPeerServer).Input(&vnetPeerInputServer{stream})
}

type VnetPeer_InputServer interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ServerStream
}

type vnetPeerInputServer struct {
	grpc.ServerStream
}

func (x *vnetPeerInputServer) Send(m *Message) error {
	return x.ServerStream.SendMsg(m)
}

func (x *vnetPeerInputServer) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _VnetPeer_serviceDesc = grpc.ServiceDesc{
	ServiceName: "VnetPeer",
	HandlerType: (*VnetPeerServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Input",
			Handler:       _VnetPeer_Input_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "protocol/protocol.proto",
}
