# shadowdhcp Installation Guide (Alpine Linux / OpenRC)

This guide covers manually installing shadowdhcp with optional ClickHouse analytics on Alpine Linux.

For easier installation, see the Installation From Repository guide.

## 1. Install shadowdhcp

### Create service user

```bash
# Create shadowdhcp user (no home directory, no login shell)
adduser -D -H -s /sbin/nologin -g "shadowdhcp service" shadowdhcp
```

### Copy the binary

```bash
# Build or copy the binary
cp shadowdhcp /usr/local/bin/shadowdhcp
chmod +x /usr/local/bin/shadowdhcp
```

### Create configuration directory

```bash
mkdir -p /etc/shadowdhcp
cp config.json /etc/shadowdhcp/
cp ids.json /etc/shadowdhcp/
cp reservations.json /etc/shadowdhcp/

# shadowdhcp reads config.json/ids.json and needs to rewrite
# reservations.json: the management `replace` command writes
# reservations.json.tmp and renames it over the original, so the service
# user needs write access to both the file and the directory.
chown root:shadowdhcp /etc/shadowdhcp /etc/shadowdhcp/config.json /etc/shadowdhcp/ids.json
chown shadowdhcp:shadowdhcp /etc/shadowdhcp/reservations.json
chmod 770 /etc/shadowdhcp
chmod 640 /etc/shadowdhcp/config.json /etc/shadowdhcp/ids.json
chmod 660 /etc/shadowdhcp/reservations.json
```

If you do not use the management interface (no `mgmt_address` in
`config.json`), nothing ever writes to this directory and you can keep it
read-only for the service instead: `chmod 750 /etc/shadowdhcp` and
`chmod 640` on all three files.

### Install the OpenRC service

```bash
cp openrc/shadowdhcp /etc/init.d/shadowdhcp
chmod +x /etc/init.d/shadowdhcp

# Create log directory
mkdir -p /var/log/shadowdhcp
chown shadowdhcp:shadowdhcp /var/log/shadowdhcp
chmod 750 /var/log/shadowdhcp
```

Don't start the service yet — configure logging first (next step) so the server doesn't run without logs.

## 2. Configure logging

The OpenRC service does not capture stdout (only stderr, for startup errors, into `/var/log/shadowdhcp/error.log`) — logs must be configured in `config.json`. Add a `logging.file` block before starting the service:

```json
"logging": {
    "file": {
        "path": "/var/log/shadowdhcp/shadowdhcp.log",
        "max_files": 3
    }
}
```

Rotation is daily, in-process; no logrotate dependency. See [logging](../docs/logging.md) for the other sinks (stdout, ClickHouse).

Then enable and start:

```bash
rc-update add shadowdhcp default
rc-service shadowdhcp start
```

## 3. ClickHouse analytics (optional)

shadowdhcp can insert DHCP events directly into ClickHouse. See [events](../docs/events.md) for the full setup, including the `clickhouse` block that goes in `config.json`.

Briefly, on your ClickHouse server, create the database and tables:

```bash
clickhouse-client --password --multiquery < clickhouse_schema.sql
```

Then test connectivity from the DHCP server:

```bash
# Test HTTP connectivity
wget -qO- "http://your-clickhouse-server:8123/ping"
# Should return: Ok.

# Test with authentication
curl -s "http://your-clickhouse-server:8123/?query=SELECT%201" \
  --user "default:your-password"
# Should return: 1
```

If you are connecting over HTTPS, make sure the CA bundle is installed:

```bash
apk add ca-certificates
```

## Service Management

```bash
service shadowdhcp start
service shadowdhcp stop
service shadowdhcp restart
service shadowdhcp reload   # Reload reservations (SIGHUP)
service shadowdhcp status
```

## File Locations

| File | Description |
|------|-------------|
| `/usr/local/bin/shadowdhcp` | DHCP server binary (cap_net_bind_service) |
| `/etc/shadowdhcp/` | Configuration files (root:shadowdhcp 770; reservations.json writable by the service for the management `replace` command) |
| `/var/log/shadowdhcp/shadowdhcp.log` | DHCP server logs (shadowdhcp:shadowdhcp 640) |
| `/var/log/shadowdhcp/error.log` | Captured stderr: startup/config errors |
| `/etc/init.d/shadowdhcp` | OpenRC service script |

## Service Users

| User | Group | Purpose |
|------|-------|---------|
| `shadowdhcp` | `shadowdhcp` | Runs DHCP server with CAP_NET_BIND_SERVICE |

## Troubleshooting

### Check if services are running

```bash
rc-status
```

### View shadowdhcp logs

```bash
tail -f /var/log/shadowdhcp/shadowdhcp.log
```

### Check user/group membership

```bash
id shadowdhcp
```
