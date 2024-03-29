package mapper

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/databeast/goatherd/internal/capture"
	packets2 "github.com/databeast/goatherd/internal/comm"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net"
	//"github.com/pkg/errors"
	"google.golang.org/grpc"
	//"net"
)

var ingestBufferSize = 10000

// Incoming Packet Summary Routing and Channels
type ingester struct {
	packets2.UnimplementedPacketCollectionServer
	grpcsrv       *grpc.Server
	incoming      chan packets2.PacketSummary
	capturepoints map[captureid]*capture.CapturePoint // packet capture source tracking for collector
}

func (i *ingester) Ingest(server packets2.PacketCollection_IngestServer) error {
	for {
		p, err := server.Recv()
		if err != nil {
			return status.Errorf(codes.Internal, err.Error())
		}
		ps := packets2.PacketSummary{}

		// process our system-order uints back into network-order byte objects
		binary.BigEndian.PutUint32(ps.SrcIP, p.GetSrcIP())
		binary.BigEndian.PutUint32(ps.DstIP, p.GetDstIP())
		binary.BigEndian.PutUint32(ps.SrcMac, p.GetSrcMac())
		binary.BigEndian.PutUint32(ps.DstMac, p.GetDstMac())

		if p.GetTTL() > 255 {
			return status.Errorf(codes.InvalidArgument, "invalid ttl: %d", p.GetTTL())
		}
		ps.TTL = uint8(p.GetTTL())

		ps.CapID = p.GetCapID()

		// send it to be processed

		i.incoming <- ps

		// TODO: if our channel is full, temporarily mark ourselves as unable to receive more
	}
}

// Register a new Remote CapturePoint
func (i *ingester) CapturePoint(ctx context.Context, req *packets2.RegisterCapturePoint) (resp *packets2.RegisterResponse, err error) {
	// idempotency for registering the same collector subnet
	for id, point := range i.capturepoints {
		if binary.BigEndian.Uint32(point.LocalNet.IP) == req.Netaddr {
			// we already know this subnet
			resp := &packets2.RegisterResponse{
				CaptureID: uint32(id),
			}
			return resp, nil
		}
	}
	// ok, its a new capture point
	point, err := capture.NewCapturePoint()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	point.LocalNet = net.IPNet{}
	binary.BigEndian.PutUint32(point.LocalNet.IP, req.Netaddr)
	point.LocalNet.Mask = net.IPMask{}
	binary.BigEndian.PutUint32(point.LocalNet.Mask, req.Netmask)

	i.capturepoints[captureid(point.ID)] = point

	resp = &packets2.RegisterResponse{
		CaptureID: point.ID,
	}
	return resp, nil

}

func (m *Mapper) Ingest(incoming <-chan packets2.PacketSummary) error {
	var p packets2.PacketSummary
	for p = range incoming {
		//p = <-incoming
		m.ingest.incoming <- p
	}
	println("ingest complete")
	return nil
}

func (m *Mapper) enableLocalIngest() (err error) {
	if m.ingest != nil {
		return errors.Errorf("ingester already exists")
	}
	m.ingest = &ingester{
		grpcsrv:       grpc.NewServer(),
		incoming:      make(chan packets2.PacketSummary, ingestBufferSize),
		capturepoints: make(map[captureid]*capture.CapturePoint),
	}
	return nil
}

func (m *Mapper) enableRemoteIngest(laddr net.IP, port uint16) (err error) {
	if m.ingest != nil {
		return errors.Errorf("ingester already exists")
	}

	m.ingest = &ingester{
		grpcsrv:  grpc.NewServer(),
		incoming: make(chan packets2.PacketSummary, ingestBufferSize),
	}

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", laddr, port))
	if err != nil {
		return errors.Errorf("unable to bind to %s:%d - %s", laddr.String(), port, err.Error())
	}

	err = m.ingest.grpcsrv.Serve(lis)
	if err != nil {
		return errors.Errorf("unable to open grpc service on %s:%d - %s", laddr.String(), port, err.Error())
	}

	packets2.RegisterPacketCollectionServer(m.ingest.grpcsrv, m.ingest)

	return nil
}

// Channel for Reading incoming comm into the Mapper
func (i *ingester) Packets() (ingestchannel <-chan packets2.PacketSummary) {
	return i.incoming
}
