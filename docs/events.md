# Events

shadowdhcp can emit JSON events for every DHCP request, enabling analytics, monitoring, and troubleshooting. Events are sent over TCP to a configurable address and can be collected by tools like Vector for storage in ClickHouse.

## Enabling events

Set the `events_address` field in `config.json` to enable event emission:

```json
{
    "events_address": "127.0.0.1:9000"
}
```

## Event structure

Events are newline-delimited JSON objects tagged with `ip_version` to distinguish DHCPv4 and DHCPv6 events.

### DHCPv4 event

Successful match by MAC address:

```json
{
    "ip_version": "v4",
    "timestamp_ms": 1704067200000,
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
    "timestamp_ms": 1704067200000,
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
| `timestamp_ms` | Unix timestamp in milliseconds. |
| `message_type` | DHCP message type: `Discover`, `Offer`, `Request`, `Ack`, `Nak`, `Release`, `Decline`. |
| `relay_addr` | IPv4 address of the relay agent. |
| `mac_address` | Client MAC address from chaddr field. |
| `option82_*` | Option 82 suboptions from the relay (circuit, remote, subscriber). |
| `reservation_*` | Fields from the matched reservation, if any. |
| `match_method` | How the reservation was found: `mac` or `option82`. |
| `extractor_used` | Which extractor matched (e.g., `chaddr`, `remote_only`). |
| `success` | Whether a reservation was found and response sent. |
| `failure_reason` | Reason for failure: `NoReservation`, `InvalidSubnet`, etc. |

### DHCPv6 event

Successful match by MAC address:

```json
{
    "ip_version": "v6",
    "timestamp_ms": 1704067200000,
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
    "timestamp_ms": 1704067200000,
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
| `timestamp_ms` | Unix timestamp in milliseconds. |
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
| `failure_reason` | Reason for failure: `NoReservation`, `NoClientId`, etc. |

## Event delivery

Events are batched and sent over TCP as newline-delimited JSON. The writer:

- Batches up to 256 events or 3 seconds of latency before sending
- Reconnects automatically if the connection is lost
- Drops events if the connection cannot be established (to prevent memory exhaustion)

When events are dropped due to connection failures, a warning is logged with the count of dropped events.

## Setting up Vector with ClickHouse

[Vector](https://vector.dev) is a lightweight observability pipeline that can receive events from shadowdhcp and forward them to ClickHouse.

### 1. Install Vector

On Alpine Linux using the Shadow Internet repository:

```bash
apk add vector-bin
```

### 2. Create ClickHouse schema

Run the schema file on your ClickHouse server to create the required tables:

```bash
clickhouse-client --password --multiquery < clickhouse_schema.sql
```

This creates:
- `dhcp.events_v4` - DHCPv4 events table
- `dhcp.events_v6` - DHCPv6 events table
- Materialized views for common aggregations (frequent clients, relay statistics)

### 3. Configure Vector

Copy the example configuration to `/etc/vector/vector.toml`:

```toml
# Sources - receive events from shadowdhcp
[sources.dhcp_events]
type = "socket"
address = "127.0.0.1:9000"
mode = "tcp"
decoding.codec = "json"

# Route events by IP version
[transforms.route_by_version]
type = "route"
inputs = ["dhcp_events"]

[transforms.route_by_version.route]
v4 = '.ip_version == "v4"'
v6 = '.ip_version == "v6"'

# Transform v4 events
[transforms.prepare_v4]
type = "remap"
inputs = ["route_by_version.v4"]
source = '''
.host_name = get_hostname!()
.success = if bool!(.success) { 1 } else { 0 }
del(.ip_version)
'''

# Transform v6 events
[transforms.prepare_v6]
type = "remap"
inputs = ["route_by_version.v6"]
source = '''
.host_name = get_hostname!()
.success = if bool!(.success) { 1 } else { 0 }
del(.ip_version)
'''

# Send to ClickHouse
[sinks.clickhouse_v4]
type = "clickhouse"
inputs = ["prepare_v4"]
endpoint = "${CLICKHOUSE_URL}"
database = "dhcp"
table = "events_v4"
skip_unknown_fields = true

auth.strategy = "basic"
auth.user = "${CLICKHOUSE_USER}"
auth.password = "${CLICKHOUSE_PASSWORD}"

batch.max_bytes = 10485760
batch.timeout_secs = 1

buffer.type = "disk"
buffer.max_size = 268435488
buffer.when_full = "block"

[sinks.clickhouse_v6]
type = "clickhouse"
inputs = ["prepare_v6"]
endpoint = "${CLICKHOUSE_URL}"
database = "dhcp"
table = "events_v6"
skip_unknown_fields = true

auth.strategy = "basic"
auth.user = "${CLICKHOUSE_USER}"
auth.password = "${CLICKHOUSE_PASSWORD}"

batch.max_bytes = 10485760
batch.timeout_secs = 1

buffer.type = "disk"
buffer.max_size = 268435488
buffer.when_full = "block"

# Drop unmatched events
[sinks.drop_unmatched]
type = "blackhole"
inputs = ["route_by_version._unmatched"]
print_interval_secs = 0
```

### 4. Configure environment variables

Create `/etc/conf.d/vector` with your ClickHouse credentials:

```bash
CLICKHOUSE_URL="http://clickhouse.example.com:8123"
CLICKHOUSE_USER="default"
CLICKHOUSE_PASSWORD="changeme"
```

### 5. Start Vector

```bash
service vector start
rc-update add vector default
```

## Example queries

Once events are flowing to ClickHouse, you can run queries like:

```sql
-- Most frequent DHCP clients
SELECT mac_address, count() as total
FROM dhcp.events_v4
GROUP BY mac_address
ORDER BY total DESC
LIMIT 10;

-- Clients without reservations
SELECT * FROM dhcp.events_v4
WHERE success = 0 AND failure_reason = 'NoReservation'
ORDER BY timestamp DESC
LIMIT 100;

-- Requests by relay
SELECT relay_addr, count() as total
FROM dhcp.events_v4
GROUP BY relay_addr
ORDER BY total DESC;

-- Match method breakdown
SELECT match_method, count() as total
FROM dhcp.events_v4
WHERE success = 1
GROUP BY match_method;

-- Extractor usage for Option82 matches
SELECT extractor_used, count() as total
FROM dhcp.events_v4
WHERE match_method = 'option82'
GROUP BY extractor_used;
```

See `clickhouse_schema.sql` for more example queries and the full schema definition.
