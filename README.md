# shadowdhcp

A reservation-only DHCPv4 and DHCPv6 server designed for internet service providers.

> **Beta Software** - This project is under active development. APIs and configuration formats may change.

## Features

* Reservation only, external software generates the reservations (e.g., ISP billing system)
* In-memory only, no database backend
* Simple configuration with `ids.json`, `config.json`, and `reservations.json`
* Only responds to relayed requests
* Correlates DHCPv6 with DHCPv4 Option 82 reservations. When premises equipment doesn't support DHCPv6 Option 37, the server uses MAC addresses learned from DHCPv4 sessions to match IPv6 requests
* Reload reservations from disk on SIGHUP or via management socket
* Analytics events for monitoring and troubleshooting
* Runs on Linux (glibc or musl), macOS, and Windows

## Quick start

See [Installation on Alpine Linux](docs/installation-alpine.md) for a complete guide.

## Configuration

`config.json`:

```json
{
    "dns_v4": ["8.8.8.8", "8.8.4.4"],
    "subnets_v4": [
        {
            "net": "100.64.0.0/24",
            "gateway": "100.64.0.1"
        }
    ],
    "option82_extractors": ["remote_only", "normalize_remote_mac"],
    "option1837_extractors": ["remote_only"]
}
```

`reservations.json`:

```json
[
    {
        "ipv4": "100.64.0.100",
        "ipv6_na": "2001:db8:1::100",
        "ipv6_pd": "2001:db8:100::/56",
        "mac": "00-11-22-33-44-55"
    },
    {
        "ipv4": "100.64.0.101",
        "ipv6_na": "2001:db8:1::101",
        "ipv6_pd": "2001:db8:101::/56",
        "option82": {"remote": "AA-BB-CC-DD-EE-FF"}
    }
]
```

## Documentation

* [Installation on Alpine Linux](docs/installation-alpine.md) - Complete installation guide
* [Configuration](docs/configuration.md) - All configuration options
* [Reservations](docs/reservations.md) - Reservation format and extractors
* [Management](docs/management.md) - TCP management interface
* [Events](docs/events.md) - Analytics events and ClickHouse setup

## Current limitations

* No high availability
* Single-threaded per protocol
* Lease times are hardcoded
* No duplicate reservation checking
* Leases and MAC to Option 82 bindings aren't persisted to disk

For a mature, full-featured DHCP server, consider the [Kea DHCP server](https://www.isc.org/kea/).
