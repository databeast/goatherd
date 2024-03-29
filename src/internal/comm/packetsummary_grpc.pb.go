// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.6.1
// source: comm/packetsummary.proto

package comm

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// PacketCollectionClient is the client API for PacketCollection service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PacketCollectionClient interface {
	// packetsummary ingest stream
	Ingest(ctx context.Context, opts ...grpc.CallOption) (PacketCollection_IngestClient, error)
	// Register a CapturePoint
	CapturePoint(ctx context.Context, in *RegisterCapturePoint, opts ...grpc.CallOption) (*RegisterResponse, error)
}

type packetCollectionClient struct {
	cc grpc.ClientConnInterface
}

func NewPacketCollectionClient(cc grpc.ClientConnInterface) PacketCollectionClient {
	return &packetCollectionClient{cc}
}

func (c *packetCollectionClient) Ingest(ctx context.Context, opts ...grpc.CallOption) (PacketCollection_IngestClient, error) {
	stream, err := c.cc.NewStream(ctx, &PacketCollection_ServiceDesc.Streams[0], "/PacketCollection/Ingest", opts...)
	if err != nil {
		return nil, err
	}
	x := &packetCollectionIngestClient{stream}
	return x, nil
}

type PacketCollection_IngestClient interface {
	Send(*PacketSummaryMessage) error
	CloseAndRecv() (*IngestResponse, error)
	grpc.ClientStream
}

type packetCollectionIngestClient struct {
	grpc.ClientStream
}

func (x *packetCollectionIngestClient) Send(m *PacketSummaryMessage) error {
	return x.ClientStream.SendMsg(m)
}

func (x *packetCollectionIngestClient) CloseAndRecv() (*IngestResponse, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(IngestResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *packetCollectionClient) CapturePoint(ctx context.Context, in *RegisterCapturePoint, opts ...grpc.CallOption) (*RegisterResponse, error) {
	out := new(RegisterResponse)
	err := c.cc.Invoke(ctx, "/PacketCollection/CapturePoint", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PacketCollectionServer is the server API for PacketCollection service.
// All implementations must embed UnimplementedPacketCollectionServer
// for forward compatibility
type PacketCollectionServer interface {
	// packetsummary ingest stream
	Ingest(PacketCollection_IngestServer) error
	// Register a CapturePoint
	CapturePoint(context.Context, *RegisterCapturePoint) (*RegisterResponse, error)
	mustEmbedUnimplementedPacketCollectionServer()
}

// UnimplementedPacketCollectionServer must be embedded to have forward compatible implementations.
type UnimplementedPacketCollectionServer struct {
}

func (UnimplementedPacketCollectionServer) Ingest(PacketCollection_IngestServer) error {
	return status.Errorf(codes.Unimplemented, "method Ingest not implemented")
}
func (UnimplementedPacketCollectionServer) CapturePoint(context.Context, *RegisterCapturePoint) (*RegisterResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CapturePoint not implemented")
}
func (UnimplementedPacketCollectionServer) mustEmbedUnimplementedPacketCollectionServer() {}

// UnsafePacketCollectionServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PacketCollectionServer will
// result in compilation errors.
type UnsafePacketCollectionServer interface {
	mustEmbedUnimplementedPacketCollectionServer()
}

func RegisterPacketCollectionServer(s grpc.ServiceRegistrar, srv PacketCollectionServer) {
	s.RegisterService(&PacketCollection_ServiceDesc, srv)
}

func _PacketCollection_Ingest_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(PacketCollectionServer).Ingest(&packetCollectionIngestServer{stream})
}

type PacketCollection_IngestServer interface {
	SendAndClose(*IngestResponse) error
	Recv() (*PacketSummaryMessage, error)
	grpc.ServerStream
}

type packetCollectionIngestServer struct {
	grpc.ServerStream
}

func (x *packetCollectionIngestServer) SendAndClose(m *IngestResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *packetCollectionIngestServer) Recv() (*PacketSummaryMessage, error) {
	m := new(PacketSummaryMessage)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _PacketCollection_CapturePoint_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterCapturePoint)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PacketCollectionServer).CapturePoint(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/PacketCollection/CapturePoint",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PacketCollectionServer).CapturePoint(ctx, req.(*RegisterCapturePoint))
	}
	return interceptor(ctx, in, info, handler)
}

// PacketCollection_ServiceDesc is the grpc.ServiceDesc for PacketCollection service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var PacketCollection_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "PacketCollection",
	HandlerType: (*PacketCollectionServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CapturePoint",
			Handler:    _PacketCollection_CapturePoint_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Ingest",
			Handler:       _PacketCollection_Ingest_Handler,
			ClientStreams: true,
		},
	},
	Metadata: "comm/packetsummary.proto",
}
