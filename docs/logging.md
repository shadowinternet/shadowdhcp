# Logging

shadowdhcp has three independently enableable log sinks, all driven by the `logging` block in `config.json`:

- **stdout** — pretty format on a TTY, newline-delimited JSON when piped.
- **file** — newline-delimited JSON to a rotating file on disk.
- **clickhouse** — JSONEachRow inserts into `dhcp.otel_logs` over HTTPS, using the connection details from the top-level `clickhouse` block. The table is ClickStack/HyperDX-compatible — point a HyperDX UI Source at `dhcp.otel_logs` and the columns map automatically.

Per-request context (MAC, xid, client DUID, relay, option82/1837 fields, match outcome) is captured by the wide DHCP event stream — see [events](events.md). Logs carry startup/shutdown messages, reservation reload results, background-writer warnings, and anything emitted via `info!`/`warn!`/`error!` during request handling.

If no `logging` block is present, shadowdhcp falls back to stdout-only (historical behavior). If a `logging` block is present but no sinks resolve to enabled, shadowdhcp prints a warning to stderr and falls back to stdout.

## Config schema

Minimal config for ClickHouse logs and a local log file at the default INFO level:

```json
"clickhouse": {
    "url": "https://clickhouse.example.com",
    "user": "dhcp_writer",
    "password": "..."
},
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
| `clickhouse` | bool | `true` when top-level `clickhouse` block present, else no-op | Toggle: insert log records into `dhcp.otel_logs` via the top-level `clickhouse` connection. |
| `queue_size` | integer | `16384` | In-memory queue capacity for the ClickHouse log sink. Records over the limit are dropped instead of back-pressuring the request path. Only applied when the ClickHouse sink is active. |

The `level` field at the top of the `logging` block gates all sinks — records below the configured level never reach any sink.

### `file`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | Required | Full log file path; directory must exist and be writable by the shadowdhcp user. |
| `max_files` | integer | `3` | Number of rotated files to keep. Older files are deleted. |

Rotation is **daily**. On each UTC-day boundary the current file is closed and a new one is opened with the date appended (e.g., `shadowdhcp.log.2026-04-23`). Records are not compressed. The active file is the one without a date suffix; historical files carry the date they cover.

### `clickhouse`

The top-level `clickhouse` block (URL, credentials, database, hostname) is shared with the events subsystem; see [Configuration → ClickHouse](configuration.md#clickhouse). The `logging.clickhouse` field is a single boolean that decides whether log records also flow to that connection. Default is `true` whenever the connection block is present, so the common case is just:

```json
"clickhouse": { "url": "...", "user": "...", "password": "..." }
```

Set `logging.clickhouse: false` to ship events to ClickHouse but keep logs out of it.

The destination table is `<database>.otel_logs` (default database is `dhcp`). Schema is in `clickhouse_schema.sql` next to the events tables.

## Batching, back-pressure, and outage behavior

The ClickHouse logs writer mirrors the events writer: bounded queue (capacity from `logging.queue_size`, default 16384 records), batches up to 2048 records or 3 seconds of latency before POSTing, retries failed batches with ~3-second sleeps (plus jitter) for up to ~5–6 minutes before dropping the in-flight batch with a warning so a wedged downstream can't pin a batch in memory forever. The in-flight batch is never grown during retry — records that arrive while ClickHouse is unreachable flow into the bounded queue. When the queue is full, new records are dropped at the producer with a count logged once per flush cycle.

On shutdown the writer drains the channel best-effort: each remaining batch gets one POST attempt, and the first failure ends the drain. The HTTP layer uses a 3 second connect timeout and a 10 second total request timeout. Drop counts are written to **stderr** rather than through tracing.

## Example queries

Once logs are flowing into `dhcp.otel_logs`, you can query directly with SQL or browse them in the HyperDX UI. SQL examples:

```sql
-- Recent errors
SELECT Timestamp, Body, LogAttributes
FROM dhcp.otel_logs
WHERE SeverityText = 'ERROR'
ORDER BY Timestamp DESC
LIMIT 100;

-- Logs for a particular MAC (set as a span field via #[instrument])
SELECT Timestamp, Body
FROM dhcp.otel_logs
WHERE LogAttributes['mac'] = '00-11-22-33-44-55'
ORDER BY Timestamp DESC;

-- Logs from a specific host
SELECT Timestamp, SeverityText, Body
FROM dhcp.otel_logs
WHERE ResourceAttributes['host.name'] = 'dhcp-01'
ORDER BY Timestamp DESC
LIMIT 100;

-- Severity histogram, last hour
SELECT SeverityText, count()
FROM dhcp.otel_logs
WHERE Timestamp > now() - INTERVAL 1 HOUR
GROUP BY SeverityText
ORDER BY 2 DESC;
```
