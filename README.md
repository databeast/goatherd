# goatherd

Goatherd passively estimates downstream IPv4 address space from Ethernet traffic. It compares source addresses forwarded
to an upstream gateway and uses observed TTLs as evidence of prior hops.

## Requirements

- Go (see the version in `src/go.mod`)
- libpcap development files to build with packet capture support (for Debian/Ubuntu: `sudo apt-get install libpcap-dev`)

## Build and test

From the repository root, GNU Make provides shortcuts for common tasks:

```sh
make build
make static
make test
make cover
make vet
make fmt
```

`make build` places a development executable in `src`; it does not guarantee static linking. `make static` requires
Docker with BuildKit and produces `build/goatherd`, a Linux executable with libpcap linked in and no dynamic loader or
shared-library dependencies. It builds for the Docker builder's native architecture. The build checks the ELF linkage
and runs the executable in an otherwise empty container. Live capture still requires suitable Linux capture privileges;
TLS clients also need an appropriate CA certificate available at runtime. The Docker image uses the same static build
and includes system CA certificates.

On a Linux deployment host, grant the executable packet-capture capability explicitly:

```sh
sudo make capture-grant
make capture-status
sudo make capture-revoke
```

These targets default to `build/goatherd`; set `CAPTURE_BINARY=/path/to/goatherd` to select the deployed executable.
They require `setcap` and `getcap` (provided by `libcap2-bin` on Debian/Ubuntu), and granting or removing capabilities
requires appropriate administrative privilege. `CAP_NET_RAW` permits raw packet capture for **any user allowed to run
the binary**; restrict executable access to trusted users. Apply capabilities only on the deployment host and
filesystem: rebuilding, copying, or replacing the executable may remove them. Offline pcap analysis does not need
capture privileges. Containers need their own runtime capability configuration and may also be subject to security
policies; file capabilities cannot override the container's capability bounding set.

The Go module is in `src`, so run Go commands from that directory:

```sh
cd src
go test ./...
go build -o goatherd .
./goatherd --help
```

## Development tools

The `src` module tracks development tools using Go's `tool` directive. Run them from `src` with `go tool`; the
first run may download their dependencies.

[Gremlins](https://github.com/go-gremlins/gremlins) performs mutation testing to check whether tests detect changes
to the code. For example:

```sh
go tool gremlins unleash ./internal/subnets --workers 1
go tool gremlins unleash --help
```

Omit the package path to test the whole module. Mutation testing can take considerably longer than `go test`; use
`--dry-run` to list mutations without testing them. On Windows, using a single worker can help avoid temporary-file
cleanup errors observed with parallel Gremlins runs.

From the repository root, the equivalent Make target runs against the whole module by default. Override the package
path or Gremlins flags as needed:

```sh
make mutation MUTATION_PATH=./internal/subnets GREMLINS_FLAGS="--workers 1"
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

Reports summarize capture quality, gateway selection, candidate prefixes, hop estimates, and possible NAT leads.
Candidate prefixes are observed-address groupings, not verified subnet boundaries; a false or absent NAT flag does
not prove NAT is absent. Use `--evidence` with `standalone` to emit the full diagnostic data, including bit/TTL
counts and prefix trees, in the chosen format instead of the summary.

Render a saved standalone JSON-LD summary (not an evidence dump) as an SVG:

```sh
./goatherd svg report.jsonld > report.svg
# Or pipe a summary directly:
./goatherd standalone --pcap capture.pcap --format jsonld | ./goatherd svg > report.svg
```

The SVG is a directed evidence graph: overall groupings point to their estimated hop-layer candidates, which point to
possible NAT evidence when present. Separate graphs show previous Ethernet hop context. Arrows represent report
grouping and evidence, not physical links or packet paths; previous hops may be hosts, bridges, proxies, or routers.
Candidate prefixes and NAT indicators are not confirmations.
The command rejects unavailable-inference reports and evidence dumps.

Standalone mode uses one local mapper capture point. The local mapper keeps evidence separate per capture-point ID.

## Distributed capture

The `mapper` command runs a central gRPC coordinator. Each `collector` streams Ethernet ARP and IPv4 observations to
one named capture point; the coordinator keeps their evidence separate and runs the same discovery logic as standalone.
Connections require mutual TLS: the coordinator and every client need a certificate and private key, and each side must
trust the other side's certificate authority. The coordinator certificate must include the host name used by clients.

On the Linux coordinator host, create a fresh deployment using Docker and GNU Make:

```sh
make deploy COORDINATOR_HOST=coordinator.example
build/deployment/goatherd-coordinator mapper --listen 0.0.0.0:8432
# Copy build/deployment/goatherd-sensor to each sensor, then on the sensor:
./goatherd-sensor collector --coordinator coordinator.example:8432 --capture-point sensor-1 --interface eth0
# On the coordinator, use the sensor binary to retrieve reports:
build/deployment/goatherd-sensor mapper reports --coordinator coordinator.example:8432
# Retrieve the consolidated address inventory:
build/deployment/goatherd-sensor mapper inventory --coordinator coordinator.example:8432
```

`make deploy` requires a Linux host with Docker. `COORDINATOR_HOST` defaults to the build host's fully qualified
hostname, falling back to its hostname. Override it with the exact DNS name or IP the sensors will use; certificate
verification requires a match. Both static Linux
binaries contain their own identity and a shared CA certificate; sensors share one client identity. Each deployment
generates a new CA and credentials valid for 30 days after the build, with one hour of clock-skew allowance. Private keys are
generated inside a temporary in-memory container filesystem and the CA key is not retained. The output directory is
private and must not already exist, to prevent accidentally replacing another deployment; choose a fresh workspace or
remove the old deployment deliberately before building again. A failed build can leave an incomplete output directory.
Treat both binaries as sensitive because their private keys can be extracted, and restrict their distribution and
execution. For live capture on a sensor, run with suitable privilege or grant capability with
`sudo setcap cap_net_raw=ep ./goatherd-sensor`.

The regular `make build` and `make static` binaries do not embed credentials. Any binary can instead use explicit PEM
files by supplying all three TLS flags, which override embedded credentials:

```sh
# Coordinator; use an appropriate bind address for remote clients.
./goatherd mapper --listen 0.0.0.0:8432 --tls-cert server.pem --tls-key server-key.pem --tls-ca client-ca.pem

# Remote host (or add --pcap capture.pcap instead of --interface).
./goatherd collector --coordinator coordinator.example:8432 --capture-point recorder-1 --interface eth0 \
  --tls-cert client.pem --tls-key client-key.pem --tls-ca server-ca.pem

# Retrieve current reports without stopping the coordinator.
./goatherd mapper reports --coordinator coordinator.example:8432 \
  --tls-cert client.pem --tls-key client-key.pem --tls-ca server-ca.pem

./goatherd mapper inventory --coordinator coordinator.example:8432 \
  --tls-cert client.pem --tls-key client-key.pem --tls-ca server-ca.pem
```

Reports are JSON arrays containing the capture point name and either its discovery report or an error explaining why
one is not yet available. The coordinator also writes this array to standard output on Ctrl+C or SIGTERM. A collector
can specify `--upstream-mac` and `--max-hops`, as in standalone mode.
Use `mapper reports --evidence` for the full diagnostic dump; `mapper --evidence` does the same for shutdown output.
The `mapper inventory` command is a separate detailed address-evidence view, not a summary report.

The `mapper inventory` command retrieves a consolidated JSON address index with per-capture-point provenance.
It includes accepted IPv4 source addresses and ARP sender addresses even when gateway inference fails; no private or
public address filter is applied. These are observations, not an automatic list of internal hosts: inbound and
internal traffic, gateway addresses, NAT, and reused addresses can all appear. Review the evidence and scan only
authorized address space. A sensor's destination-MAC counts include a subset sent toward its selected upstream MAC
and not addressed to a known ARP address of that MAC. Without a selected gateway these counts are zero, not evidence
that traffic was not outbound; without gateway ARP, traffic directed at the gateway cannot be excluded. Packet counts
are per capture point, not deduplicated across sensors. ARP MAC associations are presence-only.

Each capture point has its own `candidate_prefix_tree`, including ARP-only addresses; its packet counts cover IPv4
source observations only. Tree nodes are enclosing CIDRs derived from observed addresses, not established subnet
boundaries or recommendations to scan an entire range. Broad nodes may contain mostly unobserved space. The same IP
can appear under multiple capture points without establishing that those observations are the same host or address
realm. The top-level `candidate_prefix_tree` groups the distinct address values across all sensors, not confirmed
hosts or a shared routing realm; it deliberately has no aggregated packet counts. Quality and stream state accompany
each capture point; missing observations are not proof that space is unused.
The inventory is a live snapshot, not an atomic snapshot across sensors.
Inventory and `mapper reports` are transferred as streams of bounded gRPC messages, so the complete results are not
subject to the per-message receive-size limit. Each is still assembled in coordinator memory before transmission;
large captures can consume substantial memory. If transfer fails, the command returns an error and any output already
written is partial.

IPv4 observations include the Ethernet source MAC when supplied by a current collector. Each capture point's
`previous_hops` groups source addresses, candidate prefixes and TTL evidence by this MAC. A group is evidence of a
previous Ethernet hop, **not proof of a router**: directly attached hosts, bridges, proxying, NAT and other devices can
produce the same observation. `arp_sender_matches_previous_hop` identifies an observed ARP sender association for
that source IP, not proof that the IP is directly attached. `toward_selected_upstream` contains only packets sent to
the selected upstream MAC, excluding destinations observed as that MAC's ARP addresses; other traffic remains in
`overall`. A missing upstream selection means direction is unknown, not that no outbound traffic exists. Missing
or invalid Ethernet source MACs leave previous-hop attribution unavailable for those packets.
The same address can be associated with multiple previous hops; MACs are scoped to their capture point.
`unknown_previous_hop_packets` counts accepted IPv4 observations for which no usable source MAC was available.
Standalone reports include these groups; when inference is unavailable, the standalone quality report includes the
available address and previous-hop evidence instead.

Standalone reports include a `capture` quality snapshot; coordinator entries include `capture` and `stream_status`
even when inference is unavailable. Snapshots are sent at capture start, roughly every five seconds while running,
and at completion or failure. They show the source, status, start/update times, elapsed processing time, packets
read, and decoded ARP and IPv4 packet counts. These counts do not imply that packets were usable for inference.
An active stream with an old update may indicate a stalled sensor or transport; `disconnected` means the stream
ended unexpectedly; `stream_error` contains the coordinator's reason when available. An offline capture's elapsed
time is processing time, not the original traffic's duration.

Live snapshots include libpcap's received and drop counters when available; offline captures and sampling failures
report statistics as unavailable. Libpcap counters are platform-dependent: a zero drop or interface-drop value can
also mean that counter is unsupported, so it is not proof of lossless capture. `upstream_arp_ips` and the inference
error explain whether an upstream gateway was identified; a configured gateway without observed ARP cannot exclude
traffic addressed to the gateway itself. Standalone captures with insufficient evidence still produce a quality
report containing `inference_error` instead of a network map.

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

The evidence dump includes the source-address XOR variance mask, per-bit counts by observed TTL, assumed starting TTL,
and estimated prior hops, plus common-prefix trees for the overall observations and each hop estimate. Bit position 0
is the most significant IPv4 bit. Starting TTLs of 32, 64, 128 and 255 are considered; `--max-hops` sets the maximum
distance from a starting TTL (default 6). TTLs outside this range remain in the overall evidence with no hop estimate.

Prefix tree nodes are **candidates based on observed addresses**, not verified subnet boundaries or proof that the
entire prefix is routed. Multiple independent networks can share a tree or a hop estimate; NAT, asymmetric routing,
missing traffic, proxy ARP, and unusual initial TTLs can all affect the result. The first pass retains aggregated
source/destination/TTL observations in memory until capture ends, so memory use grows with traffic diversity.

Hop-layer candidates may include `may_contain_nat_gateway` and `nat_evidence`, also available in per-previous-hop
upstream layers and the coordinator inventory. These are currently the enclosing candidates for each hop layer,
not independent assessments of every node in a prefix tree. For a candidate formed by at least two source addresses with a prefix
no longer than /30, its depth must have strictly more observed packets within the candidate than every other known
depth. A deeper, lower-volume bucket is flagged when its addresses do not form a narrower candidate with at least two
addresses and a prefix no longer than /30. Evidence includes source addresses, counts and per-address-bit TTL counts.
Unknown TTLs are excluded. This heuristic does not establish a configured subnet or prove NAT; routed networks,
traffic imbalance, TTL assumptions and incomplete captures can produce false positives or negatives. An omitted flag
means the candidate was not assessed; `false` means this particular pattern was not observed, not that NAT is absent.
