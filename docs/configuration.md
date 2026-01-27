# Configuration

Configuration is split across two files in the config directory (default `/etc/shadowdhcp/`):

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
| `dns_v4` | Array of IPv4 addresses | DNS servers to send to clients. |
| `subnets_v4` | Array of subnet objects | IPv4 subnets the server will serve. See [Subnets](#subnets) below. |

### Optional fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `option82_extractors` | Array of strings | `[]` | Option 82 extractors for DHCPv4 reservation matching. See [reservations](reservations.md). |
| `option1837_extractors` | Array of strings | `[]` | Option 18/37 extractors for DHCPv6 reservation matching. See [reservations](reservations.md). |
| `mac_extractors` | Array of strings | `["ClientLinklayerAddress"]` | Methods for extracting MAC addresses from DHCPv6 messages. See [MAC extractors](#mac-extractors). |
| `log_level` | String | `"info"` | Log verbosity. One of: `trace`, `debug`, `info`, `warn`, `error`. |
| `events_address` | Socket address | None | Address to send JSON events to. See [events](events.md). |
| `mgmt_address` | Socket address | None | Address for the management socket. See [management](management.md). |
| `v4_bind_address` | Socket address | `"0.0.0.0:67"` | Address to bind the DHCPv4 server. |
| `v6_bind_address` | Socket address | `"[::]:547"` | Address to bind the DHCPv6 server. |

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
| `ClientLinklayerAddress` | Extract from RFC 6939 Client Link-Layer Address Option (Option 79). Most reliable; explicitly added by first-hop relay agent. |
| `PeerAddrEui64` | Extract from relay message peer address using EUI-64 reversal. Only works if client uses EUI-64 derived link-local address. |
| `Duid` | Extract from client DUID (DUID-LLT type 1 or DUID-LL type 3). Least reliable; RFC 8415 warns MAC may have changed since DUID creation. |

## Minimal example

```json
{
    "dns_v4": ["8.8.8.8", "8.8.4.4"],
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
        "ClientLinklayerAddress",
        "PeerAddrEui64"
    ],
    "log_level": "info",
    "events_address": "127.0.0.1:9000",
    "mgmt_address": "127.0.0.1:8547",
    "v4_bind_address": "0.0.0.0:67",
    "v6_bind_address": "[::]:547"
}
```
