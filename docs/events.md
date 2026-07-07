# Events

shadowdhcp can emit JSON events for every DHCP request, enabling analytics, monitoring, and troubleshooting. Two sinks are supported and can be enabled independently:

- **ClickHouse**: events are batched and inserted over HTTPS directly to ClickHouse.
- **TCP JSON lines**: events are written to a TCP socket so an external collector can consume them.

## Enabling events

Event sinks live in the `events` block, and each sink is enabled by its presence: `events.tcp` holds the TCP collector address, `events.clickhouse` holds the ClickHouse connection details:

```json
{
    "events": {
        "tcp": "127.0.0.1:9000",
        "clickhouse": {
            "url": "https://clickhouse.example.com",
            "user": "dhcp_writer",
            "password": "changeme"
        }
    }
}
```

If both are set, every event is delivered to both sinks. A stuck or unreachable sink cannot back-pressure the other.

The ClickHouse writer is gated behind the `clickhouse` cargo feature (enabled by default). To build a minimal binary without it:

```bash
cargo build --profile release-lto --no-default-features
```

## Event structure

Events are newline-delimited JSON objects tagged with `ip_version` to distinguish DHCPv4 and DHCPv6 events.

### DHCPv4 event

Successful match by MAC address:

```json
{
    "ip_version": "v4",
    "timestamp": 1704067200000,
    "message_type": "Discover",
    "relay_addr": "10.0.0.1",
    "mac_address": "00-11-22-33-44-55",
    "option82_circuit": "eth1:100",
    "option82_remote": "00-11-22-33-44-55",
    "option82_subscriber": null,
    "reservation_ipv4": "100.64.1.100",
    "reservation_mac": "00-11-22-33-44-55",
    "reservation_option82_circuit": null,
    "reservation_option82_remote": null,
    "reservation_option82_subscriber": null,
    "match_method": "mac",
    "extractor_used": "chaddr",
    "success": true,
    "failure_reason": null
}
```

No reservation found:

```json
{
    "ip_version": "v4",
    "timestamp": 1704067200000,
    "message_type": "Discover",
    "relay_addr": "10.0.0.1",
    "mac_address": "AA-BB-CC-DD-EE-FF",
    "option82_circuit": "eth1:200",
    "option82_remote": "AA-BB-CC-DD-EE-FF",
    "option82_subscriber": null,
    "reservation_ipv4": null,
    "reservation_mac": null,
    "reservation_option82_circuit": null,
    "reservation_option82_remote": null,
    "reservation_option82_subscriber": null,
    "match_method": null,
    "extractor_used": null,
    "success": false,
    "failure_reason": "NoReservation"
}
```

| Field | Description |
|-------|-------------|
| `timestamp` | Unix timestamp in milliseconds. ClickHouse parses this integer as `DateTime64(3)`. |
| `message_type` | DHCP message type: `Discover`, `Offer`, `Request`, `Ack`, `Nak`, `Release`, `Decline`. |
| `relay_addr` | IPv4 address of the relay agent. |
| `mac_address` | Client MAC address from chaddr field. |
| `option82_*` | Option 82 suboptions from the relay (circuit, remote, subscriber). |
| `reservation_*` | Fields from the matched reservation, if any. |
| `match_method` | How the reservation was found: `mac` or `option82`. |
| `extractor_used` | Which extractor matched (e.g., `chaddr`, `remote_only`). |
| `success` | Whether a reservation was found and response sent. |
| `failure_reason` | Reason for failure: `NoReservation`, `NoServerSubnet`, etc. Worker-level failures also land here: `ParseError` (undecodable datagram — `message_type` and `mac_address` are null, only `relay_addr` is known), `EncodeFailed`/`SendFailed` (a response was built but never reached the wire — reservation fields are still populated). |

### DHCPv6 event

Successful match by MAC address:

```json
{
    "ip_version": "v6",
    "timestamp": 1704067200000,
    "message_type": "Solicit",
    "xid": "a1b2c3",
    "relay_addr": "2001:db8::1",
    "relay_link_addr": "2001:db8:1::1",
    "relay_peer_addr": "fe80::1",
    "mac_address": "00-11-22-33-44-55",
    "client_id": "00:03:00:01:00:11:22:33:44:55",
    "option1837_interface": "eth0/1",
    "option1837_remote": "subscriber-001",
    "requested_ipv6_na": "2001:db8:1::100",
    "requested_ipv6_pd": "2001:db8:100::/56",
    "reservation_ipv6_na": "2001:db8:1::100",
    "reservation_ipv6_pd": "2001:db8:100::/56",
    "reservation_ipv4": "100.64.1.100",
    "reservation_mac": "00-11-22-33-44-55",
    "reservation_duid": "00:03:00:01:00:11:22:33:44:55",
    "reservation_option1837_interface": null,
    "reservation_option1837_remote": null,
    "match_method": "mac",
    "extractor_used": "client_linklayer_address",
    "success": true,
    "failure_reason": null
}
```

No reservation found:

```json
{
    "ip_version": "v6",
    "timestamp": 1704067200000,
    "message_type": "Solicit",
    "xid": "d4e5f6",
    "relay_addr": "2001:db8::1",
    "relay_link_addr": "2001:db8:1::1",
    "relay_peer_addr": "fe80::abcd",
    "mac_address": "AA-BB-CC-DD-EE-FF",
    "client_id": "00:03:00:01:AA:BB:CC:DD:EE:FF",
    "option1837_interface": "eth0/2",
    "option1837_remote": "subscriber-999",
    "requested_ipv6_na": null,
    "requested_ipv6_pd": null,
    "reservation_ipv6_na": null,
    "reservation_ipv6_pd": null,
    "reservation_ipv4": null,
    "reservation_mac": null,
    "reservation_duid": null,
    "reservation_option1837_interface": null,
    "reservation_option1837_remote": null,
    "match_method": null,
    "extractor_used": null,
    "success": false,
    "failure_reason": "NoReservation"
}
```

| Field | Description |
|-------|-------------|
| `timestamp` | Unix timestamp in milliseconds. ClickHouse parses this integer as `DateTime64(3)`. |
| `message_type` | DHCPv6 message type: `Solicit`, `Advertise`, `Request`, `Reply`, `Renew`, `Rebind`, `Release`, `Decline`. |
| `xid` | Transaction ID from the client (hex string). |
| `relay_addr` | IPv6 address the relay sent from. |
| `relay_link_addr` | Link address from relay message. |
| `relay_peer_addr` | Peer address from relay message (usually client's link-local). |
| `mac_address` | Client MAC address extracted from relay options. |
| `client_id` | Client DUID as hex string. |
| `option1837_*` | Option 18 (interface) and Option 37 (remote) from relay. |
| `requested_ipv6_*` | Addresses/prefixes the client requested. |
| `reservation_*` | Fields from the matched reservation, if any. |
| `match_method` | How the reservation was found: `mac`, `duid`, `option82`, or `option1837`. |
| `extractor_used` | Which extractor matched (e.g., `client_linklayer_address`, `remote_only`). |
| `success` | Whether a reservation was found and response sent. |
| `failure_reason` | Reason for failure: `NoReservation`, `NoClientId`, etc. Worker-level failures also land here: `ParseError` (undecodable datagram — non-nullable columns take sentinels: `message_type` = `Unknown`, empty `xid`, `::` relay link/peer), `NoRelayMsg`/`NestedRelay` (relay wrapper without a usable inner message — relay fields and MAC are populated from the wrapper), `EncodeFailed`/`SendFailed` (a response was built but never reached the wire — reservation fields are still populated). |

## Event delivery

Both writers share the same batching shape but use different batch sizes — the TCP writer flushes at 256 events or 3 seconds of latency; the ClickHouse writer flushes at 2048 events or 3 seconds. Failed flushes are retried with ~3 second sleeps (plus jitter) for up to ~5–6 minutes before the in-flight batch is dropped with a warning, so a wedged downstream can't pin a batch in memory forever.

The in-flight batch is never grown during retry — events that arrive during an outage flow into the per-sink bounded queue. When the queue is full, new events are dropped at the producer rather than back-pressuring DHCP processing; the drop count is logged once per flush cycle.

On shutdown the writers drain the channel best-effort: each remaining batch gets one flush attempt, and the first failure ends the drain. With a healthy downstream every buffered event is delivered; with a broken downstream we exit fast rather than hanging.

The TCP writer sends newline-delimited JSON and reconnects automatically if the peer drops. The ClickHouse writer uses a 3 second connect timeout and a 10 second total request timeout per POST.

## Queue sizing

Each events sink has its own bounded in-memory queue between the DHCP workers and the writer thread. When the queue is full (producer faster than the sink's sustained throughput), new events are dropped to prevent blocking DHCP processing. `events.queue_size` in `config.json` controls capacity; both sinks (TCP and ClickHouse) use the same value, each with its own channel.

Default is **16384** events per sink. Rough memory cost per queued event is a few hundred bytes, so default footprint is ~5-10 MB per sink.

## Setting up the ClickHouse writer

### 1. Create ClickHouse schema

Run the schema file on your ClickHouse server to create the required tables:

```bash
# if you installed clickhouse using the included install_clickhouse.sh script:
clickhouse-client --host clickhouse.example.com --user admin --password --port 9440 --secure --multiquery < clickhouse_schema.sql

# other installations:
clickhouse-client --password --multiquery < clickhouse_schema.sql
```

This creates:
- `dhcp.events_v4` - DHCPv4 events table
- `dhcp.events_v6` - DHCPv6 events table
- Materialized views for common aggregations (frequent clients, relay statistics)

Read the comment in `clickhouse_schema.sql` for details on creating a user that only has permission to write to the DHCP tables.

The ClickHouse table column layout closely mirrors the TCP JSON shape shown above, with one shape difference: the IPv6 prefix-delegation fields (`requested_ipv6_pd`, `reservation_ipv6_pd`) are split into separate columns — `*_prefix` (typed `IPv6`) and `*_length` (typed `UInt8`) — so prefixes can be queried with ClickHouse's IP functions (`IPv6CIDRToRange`, etc.).

### 2. Add the clickhouse block to config.json

```json
{
    "events": {
        "clickhouse": {
            "url": "https://clickhouse.example.com",
            "user": "dhcp_writer",
            "password": "REPLACE_WITH_STRONG_PASSWORD"
        }
    }
}
```

Required:
- `url`: HTTPS endpoint of the ClickHouse HTTP interface.
- `user`, `password`: credentials for the writer account created in the schema file.

Optional:
- `database`: target database, defaults to `"dhcp"`.
- `hostname`: value written into the `host_name` column of each row. If omitted, shadowdhcp reads `/etc/hostname` at startup. Set this when you want a logical name (e.g. `"dhcp-01"`) that differs from the OS hostname.

### 3. Restart shadowdhcp

On OpenRC: `rc-service shadowdhcp restart`.

## Setting up an external collector (TCP writer)

For users who want to fan events into their own pipeline, set `events.tcp` in `config.json`:

```json
{
    "events": {
        "tcp": "127.0.0.1:9000"
    }
}
```

## Example queries

See `clickhouse_schema.sql` for example queries and the full schema definition.
