# Configuration

Configuration is split across two files in the config directory (default current directory, override with `--configdir /etc/shadowdhcp`):

- `config.json` - server-wide configuration, requires restart on change
- `ids.json` - DHCP server identifiers, requires restart on change

## ids.json

Server identifiers used in DHCP responses. These should be unique per server and stable across restarts.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `v4` | IPv4 address | Yes | Server identifier for DHCPv4 responses. |
| `v6` | DUID | Yes | Server DUID for DHCPv6 responses. |

Example:

```json
{
    "v4": "10.0.11.19",
    "v6": "00:03:00:01:11:22:33:44:55:66"
}
```

## config.json

### Required fields

| Field | Type | Description |
|-------|------|-------------|
| `dns_v4` | Array of IPv4 addresses | IPv4 DNS servers to send to clients. Must contain at least one entry. |
| `dns_v6` | Array of IPv6 addresses | IPv6 DNS servers to send to clients. Must contain at least one entry. |
| `subnets_v4` | Array of subnet objects | IPv4 subnets the server will serve. See [Subnets](#subnets) below. |

### Optional fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `option82_extractors` | Array of strings | `[]` | Option 82 extractors for DHCPv4 reservation matching. See [reservations](reservations.md). |
| `option1837_extractors` | Array of strings | `[]` | Option 18/37 extractors for DHCPv6 reservation matching. See [reservations](reservations.md). |
| `mac_extractors` | Array of strings | `["client_linklayer_address"]` | Methods for extracting MAC addresses from DHCPv6 messages. See [MAC extractors](#mac-extractors). |
| `v4_lease_time` | Integer (seconds) | `3600` | DHCPv4 lease time. T1 and T2 are derived from this (RFC 2131: T1 = 0.5·lease, T2 = 0.875·lease). |
| `v6_lease_time` | Integer (seconds) | `12 * v4_lease_time` | DHCPv6 valid lifetime. Preferred/T1/T2 are derived (RFC 8415: preferred = 0.5·valid, T1 = 0.5·preferred, T2 = 0.8·preferred). See [Lease times](#lease-times) for why the v6 default is much longer than v4. |
| `logging` | Object | If not present, logs to stdout at INFO | Log level and sinks: stdout, rotating file, ClickHouse. See [logging](logging.md). |
| `clickhouse` | Object | None | ClickHouse connection (URL, credentials, database, hostname). When present, events and logs both ship here by default. See [ClickHouse](#clickhouse). |
| `events` | Object | `{}` | DHCP event sinks: TCP and/or ClickHouse toggle, plus shared queue sizing. See [events](events.md). |
| `mgmt_address` | Socket address | None | Address for the management socket. See [management](management.md). |
| `v4_bind_address` | Socket address | `"0.0.0.0:67"` | Address to bind the DHCPv4 server. |
| `v6_bind_address` | Socket address | `"[::]:547"` | Address to bind the DHCPv6 server. |

### ClickHouse

The top-level `clickhouse` block holds the connection details. Once present, both subsystems automatically use it as a sink:

- **events** insert into `dhcp.events_v4` / `dhcp.events_v6`
- **logs** insert into `dhcp.otel_logs` (HyperDX-compatible schema)

Either subsystem can opt out via its own toggle (`events.clickhouse: false` or `logging.clickhouse: false`). If the top-level block is absent, the toggles are no-ops.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | Yes | Base URL of the ClickHouse HTTP interface (e.g., `"https://clickhouse.example.com"`). |
| `user` | string | Yes | Writer account username. |
| `password` | string | Yes | Writer account password. |
| `database` | string | No | Target database. Default `"dhcp"`. |
| `hostname` | string | No | Logical hostname written into the `host_name` column on event rows and the `host.name` resource attribute on log rows. Default: contents of `/etc/hostname`. |

### Lease times

The opt82→mac binding cache is in-memory only — it's repopulated as v4 clients renew. If the server restarts, the cache is empty until each v4 client transacts again. Until then, any v6 reservation that matches purely via opt82 (no DUID, no opt18/37, no MAC) cannot be served.

The default `v6_lease_time = 12 * v4_lease_time` keeps that window small: with the default 1 hour v4 lease, all v4 clients refresh within 30 minutes of a restart, while v6 leases are 12 hours long, so the probability of a v6 lease expiring inside the refresh window is small (~4%). Clients whose v6 happens to expire in that window fall back to Solicit and self-heal on the next v4 transaction from their router. Clients renewing v6 (not expiring) just retransmit through the gap and pick up the next time the cache is populated — no lease loss.

If you don't use opt82-only reservations, the multiple is irrelevant; set whatever lease times suit you.

### Subnets

Each subnet object in `subnets_v4` defines a network the server will respond to.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `net` | CIDR notation | Yes | The subnet in CIDR notation (e.g., `100.64.0.0/24`). |
| `gateway` | IPv4 address | Yes | Default gateway to send to clients. |
| `reply_prefix_len` | Integer (0-32) | No | Override the subnet mask sent in DHCP replies. Useful for L2 customer isolation where you want clients to think they're on a /32 but still use a larger allocation internally. |

Example subnet:

```json
{
    "net": "100.64.0.0/24",
    "gateway": "100.64.0.1",
    "reply_prefix_len": 32
}
```

### MAC extractors

Methods for extracting MAC addresses from DHCPv6 messages for reservation matching. Extractors are tried in order until one succeeds.

| Extractor | Description |
|-----------|-------------|
| `client_linklayer_address` | Extract from RFC 6939 Client Link-Layer Address Option (Option 79). Most reliable; explicitly added by first-hop relay agent. |
| `peer_addr_eui64` | Extract from relay message peer address using EUI-64 reversal. Only works if client uses EUI-64 derived link-local address. |
| `duid` | Extract from client DUID (DUID-LLT type 1 or DUID-LL type 3). Least reliable; RFC 8415 warns MAC may have changed since DUID creation. |

## Minimal example

```json
{
    "dns_v4": ["8.8.8.8", "8.8.4.4"],
    "dns_v6": ["2001:4860:4860::8888", "2001:4860:4860::8844"],
    "subnets_v4": [
        {
            "net": "100.64.0.0/24",
            "gateway": "100.64.0.1"
        }
    ]
}
```

## Full example

```json
{
    "dns_v4": ["8.8.8.8", "8.8.4.4"],
    "dns_v6": ["2001:4860:4860::8888", "2001:4860:4860::8844"],
    "subnets_v4": [
        {
            "net": "100.64.0.0/22",
            "gateway": "100.64.0.1",
            "reply_prefix_len": 32
        },
        {
            "net": "100.64.4.0/24",
            "gateway": "100.64.4.1"
        }
    ],
    "option82_extractors": [
        "remote_only",
        "normalize_remote_mac",
        "circuit_and_remote"
    ],
    "option1837_extractors": [
        "remote_only",
        "interface_and_remote"
    ],
    "mac_extractors": [
        "client_linklayer_address",
        "peer_addr_eui64"
    ],
    "logging": {
        "level": "info",
        "stdout": false,
        "file": {
            "path": "/var/log/shadowdhcp/shadowdhcp.log",
            "max_files": 3
        }
    },
    "clickhouse": {
        "url": "https://clickhouse.example.com",
        "user": "dhcp_writer",
        "password": "REPLACE_WITH_STRONG_PASSWORD"
    },
    "events": {
        "tcp": "127.0.0.1:9000"
    },
    "mgmt_address": "127.0.0.1:8547",
    "v4_bind_address": "0.0.0.0:67",
    "v6_bind_address": "[::]:547"
}
```
