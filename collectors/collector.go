package collectors

import (
	"context"
	"encoding/binary"
	"github.com/databeast/goatherd/packets"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"net"
)

type Collector interface {
	Start() error
	Stop() error
	Packets() <-chan packets.PacketSummary
}

// Base Packet Collector
type collectorBase struct {
	MapperHost  string // Mapper this collector is sending to
	PacketCount int    //running count of observed packets
	pipeline    chan packets.PacketSummary
	mapperconn  packets.PacketCollectionClient
	disconnect  chan struct{} // disconnect signal
}

// connect to a remote mapper over gRPC
func (c *collectorBase) Connect(remote net.IPAddr) error {
	conn, err := grpc.Dial(remote.String())
	if err != nil {
		return errors.WithStack(err)
	}

	c.mapperconn = packets.NewPacketCollectionClient(conn)
	return nil
}

// enable local-only mode when no remote mapper configured
func (c *collectorBase) local() error {

	return nil
}

// begin feeding pipeline to gRPC stream - blocking, so call as a goroutine
func (c *collectorBase) transmit() (err error) {
	var p packets.PacketSummary
	ctx, cancel := context.WithCancel(context.Background())

	stream, err := c.mapperconn.Ingest(ctx)
	defer cancel()

	select {
		case p = <-c.pipeline:
			go func(p packets.PacketSummary) {
				msg := &packets.PacketSummaryMessage{
					CapID:                p.CapID,
					SrcIP:                binary.BigEndian.Uint32(p.SrcIP) ,
					SrcMac:               binary.BigEndian.Uint32(p.SrcMac),
					DstIP:                binary.BigEndian.Uint32(p.DstIP),
					DstMac:               binary.BigEndian.Uint32(p.DstMac),
					TTL:                  uint32(p.TTL),
				}
				err = stream.Send(msg)
				//TODO: differentiate between loss of connection and recoverable
			}(p)

		case <-c.disconnect:
			// TODO: sigv disconnect cleanup
			return errors.Errorf("sigv recieved")
	}
	return nil
}
