// Bit Mapping Tracker
// Tracks what address bits are observed to be variant, and the observed TTL values accompanied with each bit

package capture

import "net"

// TTL Tracking for each variable bit position
// if a given bitposition remains Nil, it is assumed to be invariant
type BitMap [32]*ttlbittrack

type ttlbittrack struct {
	value     bitval          // either a fixed value, or mark that it is variant
	ttlcounts map[uint8]int64 // TTL observed, with number of packets observed with this value on this bit
}

type bitval int8

const (
	UNSET   bitval = 0
	SET     bitval = 1
	VARIANT bitval = 2
)

func (g *Gateway) trackBitTTL(position uint8, ttlstep uint8) {
	//NOT A THREAD-SAFE CALL, only use within existing mutex lock
	g.bitmapping[position].ttlcounts[ttlstep] += 1
}

// start with a given subnet and prefix
// 1101 0101 1101 0110 1000 0111 / 24
//
// identify bits that change beneath this. These are legit host source address bits
//
// identify which bits remain unchanged no matter how much traffic is seen
//
//
//
// remember that Network and Broadcast Addresses should never be seen as a source address
//
// This assists us in identifying potential subnet masks, especially on non-octet boundaries

//


// turn IP addresses into a bitmap style array of bools, its just easier to work with that way
func decomposeToBits(addr net.IP) (bits [32]bool, err error) {

	//ipint := binary.BigEndian.Uint32(addr)
	//NOTE: validate this goes bigendian in all archs
	for i, x := range addr {
		for j := 0; j < 8; j++ {
			if (x<<uint(j))&0x80 == 0x80 {
				bits[8*i+j] = true
			}
		}
	}

	return bits, err
}


