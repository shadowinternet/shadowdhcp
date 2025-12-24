# shadow_dhcpv6 Installation Guide (Alpine Linux / OpenRC)

This guide covers installing shadow_dhcpv6 with optional Vector telemetry on Alpine Linux.

## Prerequisites

```bash
apk add logrotate libcap
```

## 1. Install shadowdhcp

### Create service user

```bash
# Create shadowdhcp user (no home directory, no login shell)
adduser -D -H -s /sbin/nologin -g "shadow_dhcpv6 service" shadowdhcp
```

### Copy the binary

```bash
# Build or copy the binary
cp shadowdhcp /usr/local/bin/shadowdhcp
chmod +x /usr/local/bin/shadowdhcp

# Allow binding to privileged ports (67/udp for DHCPv4, 547/udp for DHCPv6)
setcap 'cap_net_bind_service=+ep' /usr/local/bin/shadowdhcp
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

# Create log directory (group-readable for vector)
mkdir -p /var/log/shadowdhcp
chown shadowdhcp:shadowdhcp /var/log/shadowdhcp
chmod 750 /var/log/shadowdhcp

# Enable and start
rc-update add shadowdhcp default
rc-service shadowdhcp start
```

### Install logrotate configuration

```bash
cp openrc/shadowdhcp.logrotate /etc/logrotate.d/shadowdhcp
```

Logrotate runs daily via cron. To test manually:

```bash
logrotate -f /etc/logrotate.d/shadowdhcp
```

## 2. Install Vector (Optional - for telemetry)

Vector collects DHCP events and traces, sending them to ClickHouse.

### Create service user

```bash
# Create vector user and add to shadowdhcp group (to read logs)
adduser -D -H -s /sbin/nologin -g "Vector service" vector
addgroup vector shadowdhcp
```

### Install Vector

```bash
# Download and extract just the binary
VECTOR_VERSION="0.52.0"
cd /tmp
wget "https://packages.timber.io/vector/${VECTOR_VERSION}/vector-${VECTOR_VERSION}-x86_64-unknown-linux-musl.tar.gz"
tar -xzf "vector-${VECTOR_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
    --strip-components=3 -C /usr/local/bin \
    "./vector-x86_64-unknown-linux-musl/bin/vector"
rm "vector-${VECTOR_VERSION}-x86_64-unknown-linux-musl.tar.gz"

# Verify installation
vector --version
```

For ARM64 (aarch64), use `aarch64-unknown-linux-musl` instead.

### Create directories

```bash
mkdir -p /etc/vector /var/lib/vector /var/log/vector
chown vector:vector /var/lib/vector /var/log/vector
```

### Install Vector configuration

```bash
cp vector.toml /etc/vector/vector.toml
```

### Configure ClickHouse credentials

```bash
cp openrc/vector.conf /etc/conf.d/vector
chmod 640 /etc/conf.d/vector

# Edit with your ClickHouse settings
vi /etc/conf.d/vector
```

Set the following in `/etc/conf.d/vector`:

```bash
CLICKHOUSE_URL="http://your-clickhouse-server:8123"
CLICKHOUSE_USER="default"
CLICKHOUSE_PASSWORD="your-password"
```

### Install the OpenRC service

```bash
cp openrc/vector /etc/init.d/vector
chmod +x /etc/init.d/vector

# Enable and start
rc-update add vector default
rc-service vector start
```

### Verify Vector is running

```bash
rc-service vector status
tail -f /var/log/vector/vector.log
```

## 3. ClickHouse Setup

On your ClickHouse server, create the database and tables:

```bash
clickhouse-client --password --multiquery < clickhouse_schema.sql
```

### Test connectivity from the DHCP server

```bash
# Test HTTP connectivity
wget -qO- "http://your-clickhouse-server:8123/ping"
# Should return: Ok.

# Test with authentication
curl -s "http://your-clickhouse-server:8123/?query=SELECT%201" \
  --user "default:your-password"
# Should return: 1
```

## Service Management

### shadowdhcp

```bash
rc-service shadowdhcp start
rc-service shadowdhcp stop
rc-service shadowdhcp restart
rc-service shadowdhcp status
```

### Vector

```bash
rc-service vector start
rc-service vector stop
rc-service vector restart
rc-service vector status

# Validate configuration
vector validate /etc/vector/vector.toml
```

## File Locations

| File | Description |
|------|-------------|
| `/usr/local/bin/shadowdhcp` | DHCP server binary (cap_net_bind_service) |
| `/etc/shadowdhcp/` | Configuration files (root:shadowdhcp 750) |
| `/var/log/shadowdhcp/shadowdhcp.log` | DHCP server logs (shadowdhcp:shadowdhcp 640) |
| `/etc/init.d/shadowdhcp` | OpenRC service script |
| `/usr/local/bin/vector` | Vector binary |
| `/etc/vector/vector.toml` | Vector configuration |
| `/etc/conf.d/vector` | Vector environment variables (640) |
| `/var/lib/vector/` | Vector disk buffer (vector:vector) |
| `/var/log/vector/` | Vector logs (vector:vector) |
| `/etc/init.d/vector` | Vector OpenRC service script |
| `/etc/logrotate.d/shadowdhcp` | Log rotation config |

## Service Users

| User | Group | Purpose |
|------|-------|---------|
| `shadowdhcp` | `shadowdhcp` | Runs DHCP server with CAP_NET_BIND_SERVICE |
| `vector` | `vector`, `shadowdhcp` | Runs Vector, reads shadowdhcp logs |

## Troubleshooting

### Check if services are running

```bash
rc-status
```

### View shadowdhcp logs

```bash
tail -f /var/log/shadowdhcp/shadowdhcp.log
```

### View Vector logs

```bash
tail -f /var/log/vector/vector.log
tail -f /var/log/vector/vector.err
```

### Test DHCP event ingestion

```bash
# Send a test event to Vector
echo '{"ip_version":"v4","test":true}' | nc localhost 9000
```

### Validate Vector config

```bash
CLICKHOUSE_URL="http://localhost:8123" \
CLICKHOUSE_USER="default" \
CLICKHOUSE_PASSWORD="test" \
vector validate /etc/vector/vector.toml
```

### Verify capabilities

```bash
getcap /usr/local/bin/shadowdhcp
# Should show: /usr/local/bin/shadowdhcp cap_net_bind_service=ep
```

### Check user/group membership

```bash
id shadowdhcp
id vector
# vector should be in both 'vector' and 'shadowdhcp' groups
```
