# Logging

shadowdhcp has two independently enableable log sinks, both driven by the `logging` block in `config.json`:

- **stdout** — pretty format on a TTY, newline-delimited JSON when piped.
- **file** — newline-delimited JSON to a rotating file on disk.

Per-request context (MAC, xid, client DUID, relay, option82/1837 fields, match outcome) is captured by the wide DHCP event stream — see [events](events.md). That includes malformed and undeliverable traffic: undecodable datagrams and encode/send failures are emitted as events with `failure_reason` values `ParseError`, `NoRelayMsg`, `NestedRelay`, `EncodeFailed`, or `SendFailed`, so they are visible in ClickHouse/Grafana without log access.

At `info` the log is a one-line-per-transaction narrative, emitted at the worker send path so it reflects what actually went out on the wire: lease offered/acknowledged/granted (with MAC, IP, match method, relay, xid), NAK sent, NoBinding reply, or no-reservation-found with the request's raw identifiers (MAC, DUID, option 82/18/37 values). The per-extractor lookup attempts derived from those identifiers are visible at `debug!`. Alongside that narrative, logs carry startup/shutdown messages, reservation reload results, and operator-actionable `warn!`/`error!` conditions (config gaps, socket errors, writer drops). Step-by-step internals live at `debug!`/`trace!`.

If no `logging` block is present, shadowdhcp falls back to stdout-only (historical behavior). If a `logging` block is present but no sinks resolve to enabled, shadowdhcp prints a warning to stderr and falls back to stdout.

For centralized/remote log search, point a log shipper (vector, promtail, journald forwarding) at the JSON file sink or at supervised stdout — both emit machine-parseable JSON lines when not attached to a TTY.

## Config schema

Minimal config for a local log file at the default INFO level:

```json
"logging": {
    "file": {
        "path": "/var/log/shadowdhcp/shadowdhcp.log",
        "max_files": 3
    }
}
```

### Top-level `logging` fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `level` | string | `"info"` | Log verbosity. One of: `trace`, `debug`, `info`, `warn`, `error`. Gates every sink. |
| `stdout` | bool | `true` | Write to stdout. |
| `file` | object | None | Enable rotating file sink. See below. |

The `level` field at the top of the `logging` block gates all sinks — records below the configured level never reach any sink.

### `file`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | Required | Full log file path; directory must exist and be writable by the shadowdhcp user. |
| `max_files` | integer | `3` | Number of rotated files to keep. Older files are deleted. |

Rotation is **daily**. On each UTC-day boundary the current file is closed and a new one is opened with the date appended (e.g., `shadowdhcp.log.2026-04-23`). Records are not compressed. The active file is the one without a date suffix; historical files carry the date they cover.
