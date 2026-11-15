# goatherd

Goatherd passively estimates downstream IPv4 address space from Ethernet traffic. It compares source addresses forwarded
to an upstream gateway and uses observed TTLs as evidence of prior hops.

## Requirements

- Go (see the version in `src/go.mod`)
- libpcap development files to build with packet capture support (for Debian/Ubuntu: `sudo apt-get install libpcap-dev`)

## Build and test

The Go module is in `src`, so run Go commands from that directory:

```sh
cd src
go test ./...
go build -o goatherd .
./goatherd --help
```

## Run

Analyze an Ethernet capture file:

```sh
./goatherd standalone --pcap capture.pcap
```

Or capture live traffic, then press Ctrl+C to produce a report:

```sh
./goatherd standalone --interface eth0
```

Live capture uses promiscuous mode and typically requires elevated privileges. The capture point must actually see
traffic forwarded toward the upstream gateway; a normal switched host interface may not see other hosts' traffic.
IPv6 and non-Ethernet captures are not supported.

Automatic gateway selection requires ARP sender advertisements in the capture. Among MAC addresses with an ARP
association, goatherd selects the one with the most IPv4 packets whose destination is not one of that MAC's advertised
IPs. Candidate counts are included in the report; a tie or lack of ARP evidence is an error. If the gateway is known
but its ARP traffic is absent, use `--upstream-mac 02:00:00:00:00:01`. Without an observed ARP association, packets
addressed directly to that gateway cannot be excluded.

The JSON report includes the source-address XOR variance mask, per-bit counts by observed TTL, assumed starting TTL,
and estimated prior hops, plus common-prefix trees for the overall observations and each hop estimate. Bit position 0
is the most significant IPv4 bit. Starting TTLs of 32, 64, 128 and 255 are considered; `--max-hops` sets the maximum
distance from a starting TTL (default 6). TTLs outside this range remain in the overall evidence with no hop estimate.

Prefix tree nodes are **candidates based on observed addresses**, not verified subnet boundaries or proof that the
entire prefix is routed. Multiple independent networks can share a tree or a hop estimate; NAT, asymmetric routing,
missing traffic, proxy ARP, and unusual initial TTLs can all affect the result. The first pass retains aggregated
source/destination/TTL observations in memory until capture ends, so memory use grows with traffic diversity.
