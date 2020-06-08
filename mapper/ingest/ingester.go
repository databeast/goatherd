package ingest

import (
	"context"
	"github.com/databeast/goatherd/packets"
	"google.golang.org/grpc"
)

type ingestsrv struct {
	grpcsrv *grpc.Server
}

func (i *ingestsrv) Ingest(server packets.PacketCollection_IngestServer) error {
	panic("implement me")
}

func (i *ingestsrv) CapturePoint(ctx context.Context, point *packets.RegisterCapturePoint) (*packets.RegisterResponse, error) {
	panic("implement me")
}

var ingester *ingestsrv

func BeginRemoteIngest() {
	ingester = &ingestsrv{
		grpcsrv: grpc.NewServer(),
	}

	packets.RegisterPacketCollectionServer(ingester.grpcsrv, ingester)

}
