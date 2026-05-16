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

# Allow shadowdhcp user to read config
chown -R root:shadowdhcp /etc/shadowdhcp
chmod 750 /etc/shadowdhcp
chmod 640 /etc/shadowdhcp/*
```

### Install the OpenRC service

```bash
cp openrc/shadowdhcp /etc/init.d/shadowdhcp
chmod +x /etc/init.d/shadowdhcp

# Create log directory
mkdir -p /var/log/shadowdhcp
chown shadowdhcp:shadowdhcp /var/log/shadowdhcp
chmod 750 /var/log/shadowdhcp

# Enable and start
rc-update add shadowdhcp default
rc-service shadowdhcp start
```

## 2. Configure logging

The OpenRC service does not capture stdout — logs must be configured in `config.json`. Add a `logging.file` block before starting the service:

```json
"logging": {
    "file": {
        "path": "/var/log/shadowdhcp/shadowdhcp.log",
        "max_files": 3
    }
}
```

Rotation is daily, in-process; no logrotate dependency. See [logging](../docs/logging.md) for the other sinks (stdout, ClickHouse).

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
| `/etc/shadowdhcp/` | Configuration files (root:shadowdhcp 750) |
| `/var/log/shadowdhcp/shadowdhcp.log` | DHCP server logs (shadowdhcp:shadowdhcp 640) |
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
