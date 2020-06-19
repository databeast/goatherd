// Bit Mapping Tracker
// Tracks what address bits are observed to be variant, and the observed TTL values accompanied with each bit

package capture

import "net"

type bitposition uint8

const (
	bit0 bitposition = iota
	bit1
	bit2
	bit3
	bit4
	bit5
	bit6
	bit7
	bit8
	bit9
	bit10
	bit11
	bit12
	bit13
	bit14
	bit15
	bit16
	bit17
	bit18
	bit19
	bit20
	bit21
	bit22
	bit23
	bit24
	bit25
	bit26
	bit27
	bit28
	bit29
	bit30
	bit31
)

// TTL Tracking for each variable bit position
// if a given bitposition remains Nil, it is assumed to be invariant
type BitMap map[bitposition]ttltrack

type ttltrack map[uint8]ttlbittrack

type ttlbittrack struct {
	value bitval   // either a fixed value, or mark that it is variant
	ttlcounts map[int8]int8  // TTL observed, with number of packets observed with this value on this bit
}

type bitval int8
const  (
	SET bitval = 0
	UNSET bitval = 1
	VARIANT bitval = 2
)


func (g *Gateway) trackBitTTL(position bitposition, ttlstep uint8) {
	g.bitmu.Lock()
	g.bitmapping[position][ttlstep] += 1
	g.bitmu.Unlock()
}

// break down address into bigendian bits, marking the probable step for each
// This function is useless if applied on source addresses coming from upstream gateways
func decomposeTtlBits(addr net.IPAddr, ttl uint8) {

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
