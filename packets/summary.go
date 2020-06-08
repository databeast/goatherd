package packets

import (
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v5"
	"net"
)

type PacketSummary struct {
	SrcIP  net.IP
	SrcMac net.HardwareAddr
	DstIP  net.IP
	DstMac net.HardwareAddr
	TTL    uint8
	CapID  uint32 //capturepoint this packetsummary was taken from
}

func (s PacketSummary) Marshall() ([]byte, error) {
	b, err := msgpack.Marshal(&s)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return b, nil
}

func UnmarshallSummary(data []byte) (summary PacketSummary, err error) {
	err = msgpack.Unmarshal(data, &summary)
	return summary, err
}
