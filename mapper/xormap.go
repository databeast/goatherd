// XOR Processor - determines if a given 32-bit integer falls within a XOR-masked 32bit integer
// This is the same process IPv4 uses to determine if an IP address matches a given Subnet

package mapper

// Exclusive-OR bitmasking for subnet identification
type XorMap struct {

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


