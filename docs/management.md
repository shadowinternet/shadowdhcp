# Management socket

The server can be configured to listen for newline-delimited JSON messages over TCP to update reservations or receive server status.

Configure the server to listen in `config.json`:

```json
{
    ... other config

    "mgmt_address": "127.0.0.1:8547"
}
```

## Message types

* Reload - reload reservations from `reservations.json`
* Replace - supply a list of reservations to replace all existing reservations in `reservations.json`
* Status - get server status

See `mgmt::MgmtRequest` and `mgmt::MgmtResponse` for the Rust definitions.

## Example messages

### status

Check server health and get the current reservation count.

```json
{"command":"status"}
```

Response:
```json
{"success":true,"message":"Status OK","reservation_count":42}
```

### reload

Reload reservations from the `reservations.json` file on disk.

```json
{"command":"reload"}
```

Response:
```json
{"success":true,"message":"Reloaded 42 reservations","reservation_count":42}
```

### replace

Replace all reservations with a new set. The new reservations are persisted to disk, completely replacing the existing reservations.

```json
{"command":"replace","reservations":[{"ipv4":"100.64.1.1","ipv6_na":"2001:db8::1","ipv6_pd":"2001:db8:1::/56","mac":"00-11-22-33-44-55"}]}
```

Response:
```json
{"success":true,"message":"Replaced with 1 reservations","reservation_count":1}
```

### Error response

Applies to any command:
```json
{"success":false,"error":"Invalid request: missing field `command`"}
```
