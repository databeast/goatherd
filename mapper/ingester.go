package mapper

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/databeast/goatherd/packets"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"net"
	"google.golang.org/grpc/status"
	//"github.com/pkg/errors"
	"google.golang.org/grpc"
	//"net"
)

var ingestBufferSize = 10000

// Incoming Packet Summary Routing and Channels
type ingester struct {
	grpcsrv *grpc.Server
	incoming chan packets.PacketSummary
}

func (i *ingester) Ingest(server packets.PacketCollection_IngestServer) error {
	for {
		p, err := server.Recv()
		if err != nil {
			return status.Errorf(codes.Internal, err.Error())
		}
		ps := packets.PacketSummary{}

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
func (i *ingester) CapturePoint(ctx context.Context, point *packets.RegisterCapturePoint) (*packets.RegisterResponse, error) {
	panic("implement me")
}

func (m *Mapper) enableLocalIngest() (err error){
	if m.ingest != nil {
		return errors.Errorf("ingester already exists")
	}
	m.ingest = &ingester{
		grpcsrv: grpc.NewServer(),
		incoming: make(chan packets.PacketSummary, ingestBufferSize),
	}
	return nil
}

func (m *Mapper) enableRemoteIngest(laddr net.IP, port uint16) (err error) {
	if m.ingest != nil {
		return errors.Errorf("ingester already exists")
	}

	m.ingest = &ingester{
		grpcsrv: grpc.NewServer(),
		incoming: make(chan packets.PacketSummary, ingestBufferSize),
	}

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", laddr, port))
	if err != nil {
		return errors.Errorf("unable to bind to %s:%d - %s", laddr.String(), port, err.Error())
	}

	err = m.ingest.grpcsrv.Serve(lis)
	if err != nil {
		return errors.Errorf("unable to open grpc service on %s:%d - %s", laddr.String(), port, err.Error())
	}

	packets.RegisterPacketCollectionServer(m.ingest.grpcsrv, m.ingest)

	return nil
}



// Channel for Reading incoming packets into the Mapper
func (i *ingester) Packets() (ingestchannel <-chan packets.PacketSummary) {
	return i.incoming
}
