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

The default report format is JSON. For a human-readable report, add `--format text`. Use `--format jsonld` for JSON-LD
with an inline context: the report is a Schema.org `Dataset`, while discovery-specific terms use the
`https://github.com/databeast/goatherd#` namespace. The namespace identifies project-defined terms; it is not a hosted
JSON-LD context or a claim that those terms are part of Schema.org. JSON-LD processors omit null values from the RDF
graph, so an unavailable TTL estimate is represented by absent properties there.

Standalone mode uses one local mapper capture point. The local mapper keeps evidence separate per capture-point ID.

## Distributed capture

The `mapper` command runs a central gRPC coordinator. Each `collector` streams Ethernet ARP and IPv4 observations to
one named capture point; the coordinator keeps their evidence separate and runs the same discovery logic as standalone.
Connections require mutual TLS: the coordinator and every client need a certificate and private key, and each side must
trust the other side's certificate authority. The coordinator certificate must include the host name used by clients.

```sh
# Coordinator; use an appropriate bind address for remote clients.
./goatherd mapper --listen 0.0.0.0:8432 --tls-cert server.pem --tls-key server-key.pem --tls-ca client-ca.pem

# Remote host (or add --pcap capture.pcap instead of --interface).
./goatherd collector --coordinator coordinator.example:8432 --capture-point recorder-1 --interface eth0 \
  --tls-cert client.pem --tls-key client-key.pem --tls-ca server-ca.pem

# Retrieve current reports without stopping the coordinator.
./goatherd mapper reports --coordinator coordinator.example:8432 \
  --tls-cert client.pem --tls-key client-key.pem --tls-ca server-ca.pem
```

Reports are JSON arrays containing the capture point name and either its discovery report or an error explaining why
one is not yet available. The coordinator also writes this array to standard output on Ctrl+C or SIGTERM. A collector
can specify `--upstream-mac` and `--max-hops`, as in standalone mode.

Capture point names must be unique for the lifetime of the coordinator. A disconnected collector cannot resume the
same name; its accumulated evidence remains available until the coordinator exits. State is held in memory and is lost
on restart. The coordinator trusts any client certificate signed by its configured CA for both submissions and report
access; use a dedicated CA for this trusted group. The coordinator does not currently enforce per-client authorization,
automatic retries, persistence, or bounded observation storage.

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
