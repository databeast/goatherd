package mapper

import (
	"context"
	"encoding/binary"
	"github.com/databeast/goatherd/packets"
	//"github.com/pkg/errors"
	"google.golang.org/grpc"
	//"net"
)

// Incoming Packet Summary Routing and Channels
type ingester struct {
	grpcsrv *grpc.Server
	incoming chan packets.PacketSummary
}

func (i *ingester) Ingest(server packets.PacketCollection_IngestServer)  {
	go func() {
		p, err := server.Recv()
		if err != nil {

		}
		ps := packets.PacketSummary{}

		// process our system-order uints back into network-order byte objects
		binary.BigEndian.PutUint32(ps.SrcIP, p.GetSrcIP())
		binary.BigEndian.PutUint32(ps.DstIP, p.GetDstIP())
		binary.BigEndian.PutUint32(ps.SrcMac, p.GetSrcMac())
		binary.BigEndian.PutUint32(ps.DstMac, p.GetDstMac())

		if p.GetTTL() > 255 {
			//errors.Errorf("invalid ttl: %d", p.GetTTL())
		} else {
			ps.TTL = uint8(p.GetTTL())
		}

		ps.CapID = p.GetCapID()

		// send it to be processed

		i.incoming <- ps

		// TODO: if our channel is full, temporarily mark ourselves as unable to receive more

	}()

}

func (i *ingester) CapturePoint(ctx context.Context, point *packets.RegisterCapturePoint) (*packets.RegisterResponse, error) {
	panic("implement me")
}


func BeginRemoteIngest() (*ingester, error){
	ingest := &ingester{
		grpcsrv: grpc.NewServer(),
	}

	packets.RegisterPacketCollectionServer(ingest.grpcsrv, ingest)

	return ingest, nil
}



// Channel for Reading incoming packets into the Mapper
func (i *ingester) Packets() (ingestchannel chan packets.PacketSummary) {
	return i.incoming
}
