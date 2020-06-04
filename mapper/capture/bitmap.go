// Bit Mapping Tracker
// Tracks what address bits are observed to be variant, and the observed TTL values accompanied with each bit

package capture

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

type ttltrack map[uint8]int64

// TTL Tracking for each variable bit position
// if a given bitposition remains Nil, it is assumed to be invariant
type BitMap map[bitposition]*ttltrack


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
