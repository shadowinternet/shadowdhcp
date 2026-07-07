# Management socket

The server can be configured to listen for newline-delimited JSON messages over TCP to update reservations or receive server status.

Configure the server to listen in `config.json`:

```json
{
    ... other config

    "mgmt_address": "127.0.0.1:8547"
}
```

## Security

The management interface has full write access to reservations and no authentication, so `mgmt_address` **must be a loopback address** (e.g. `127.0.0.1` or `[::1]`) — the server refuses to start otherwise. The trust model is the same as a unix domain socket without restrictive file permissions: any process on the machine can connect, but nothing off the machine can. TCP is used instead of a unix socket so the interface works identically on Windows.

The intended integration is a companion process running on the same machine as shadowdhcp — for example, a small daemon that pulls reservations from your billing system and pushes them with `replace`.

If the connection closes without a response (for example, the server shut down mid-request), the outcome is indeterminate: a `replace` may or may not have persisted. Reservation persistence is an atomic write+rename, so the file is never corrupted — reconnect and verify with `status`, or simply resend; `replace` is idempotent.

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
