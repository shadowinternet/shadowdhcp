# Reservations

Reservations are stored in `reservations.json` and can be hot reloaded by sending SIGHUP or using the [management](management.md) interface.

## Requirements

Each reservation must have:

* `ipv4`
* `ipv6_na`
* `ipv6_pd`
* at least one source for ipv4 and one source for ipv6

Available IPv4 sources in priority order:

* `mac` - MAC address
* `option82` - Option 82 data

Available IPv6 sources in priority order:

* `duid` - DUID
* `option1837` - Option 18 and Option 37 data
* `mac` - MAC address
* `option82` - Option 82 data


## Examples

Below are individual examples with explanations. See the end for a full file.

### MAC address only

```json
{
    "ipv4": "192.168.0.100",
    "ipv6_na": "2001:db8:1::2",
    "ipv6_pd": "2001:db8:2::/56",
    "mac": "00-11-22-33-44-55"
}
```

### Option82 only

The Option82 object has three fields: `remote`, `circuit`, and `subscriber`.

The server supports transforming received Option82 data before comparing with the reservations in `reservations.json`. After extraction, fields are compared as strings. If you include MAC addresses in option82 fields, format them as all caps with dashes (e.g., `00-11-22-33-44-55`).

Available extractors (configured in `config.json` under `option82_extractors`):

| Extractor | Description |
|-----------|-------------|
| `remote_only` | Extract the Remote-ID only if it exists. |
| `remote_only_trim` | Extract the Remote-ID, trimming whitespace and trailing null characters. |
| `circuit_only` | Extract the Circuit-ID only if it exists. |
| `circuit_and_remote` | Extract both Circuit-ID and Remote-ID. Only succeeds if both exist. |
| `subscriber_only` | Extract the Subscriber-ID only if it exists. |
| `remote_first_12` | Parse the first 12 characters of Remote-ID as a MAC address, then format with dashes (e.g., `AC-8B-A9-E2-17-F8`). |
| `normalize_remote_mac` | Parse the entire Remote-ID as a MAC address and re-encode with dashes. Useful when the relay sends MACs in varying formats. |


This will match only if at least one of the remote_only extractors is configured (`remote_only`, `remote_only_trim`, `remote_first_12`, `normalize_remote_mac`):

```json
{
    "ipv4": "192.168.0.100",
    "ipv6_na": "2001:db8:1::2",
    "ipv6_pd": "2001:db8:2::/56",
    "option82": {"remote": "00-11-22-33-44-55"}
}
```

This will match only if circuit and remote appear exactly as sent (`circuit_and_remote` extractor enabled):

```json
{
    "ipv4": "192.168.0.100",
    "ipv6_na": "2001:db8:1::2",
    "ipv6_pd": "2001:db8:2::/56",
    "option82": {"circuit": "eth1:100", "remote": "00:11:22:33:44:55"}
}
```

This will match subscriber (`subscriber_only` extractor enabled):

```json
{
    "ipv4": "192.168.0.100",
    "ipv6_na": "2001:db8:1::2",
    "ipv6_pd": "2001:db8:2::/56",
    "option82": {"subscriber": "subscriber:100"}
}
```

### Option82 and Option1837

See above for required Option82 extractors.

The Option1837 object has three fields: `interface` (Option 18), `remote` (Option 37), and `enterprise_number` (Option 37). After extraction, fields are compared as strings.

Available extractors (configured in `config.json` under `option1837_extractors`):

| Extractor | Description |
|-----------|-------------|
| `interface_only` | Extract the Interface-ID (Option 18) only if it exists. |
| `remote_only` | Extract the Remote-ID (Option 37) only if it exists. |
| `interface_and_remote` | Extract both Interface-ID and Remote-ID. Only succeeds if both exist. |
| `remote_with_enterprise` | Extract Remote-ID with enterprise number. Only succeeds if both exist. |
| `all_fields` | Extract all fields if at least interface or remote exists. |

```json
{
    "ipv4": "192.168.0.100",
    "ipv6_na": "2001:db8:1::2",
    "ipv6_pd": "2001:db8:2::/56",
    "option82": {"remote": "00-11-22-33-44-55"},
    "option1837": {"remote": "00-11-22-33-44-55"}
}
```

### MAC with DUID for IPv6

DUID for IPv6, MAC for IPv4.

```json
{
    "ipv4": "192.168.0.100",
    "ipv6_na": "2001:db8:1::2",
    "ipv6_pd": "2001:db8:2::/56",
    "mac": "00-11-22-33-44-55",
    "duid": "00:03:00:01:11:22:33:44:55:66"
}
```

### Example file

`reservations.json`:

```json
[
    {
        "ipv4": "192.168.1.109",
        "ipv6_na": "2001:db8:1:2::1",
        "ipv6_pd": "2001:db8:1:3::/56",
        "mac": "00-11-22-33-44-55"
    },
    {
        "ipv4": "192.168.1.110",
        "ipv6_na": "2001:db8:1:4::1",
        "ipv6_pd": "2001:db8:1:5::/56",
        "mac": "00-11-22-33-44-57",
        "duid": "00:03:00:01:00:11:22:33:44:57"
    },
    {
        "ipv4": "192.168.1.111",
        "ipv6_na": "2001:db8:1:6::1",
        "ipv6_pd": "2001:db8:1:7::/56",
        "option82": {"circuit": "99-11-22-33-44-55", "remote": "eth2:100"}
    },
    {
        "ipv4": "192.168.1.112",
        "ipv6_na": "2001:db8:1:8::1",
        "ipv6_pd": "2001:db8:1:9::/56",
        "duid": "29:30:31:32:33:34:35:36:37:38:39:40:41:42:43:44",
        "option82": {"subscriber": "subscriber:1020"}
    },
    {
        "ipv4": "100.110.1.2",
        "ipv6_na": "2001:db8:1::2",
        "ipv6_pd": "2001:db8:2::/56",
        "option82": {"remote": "AC-8B-A9-E2-17-F8"}
    }
]
```