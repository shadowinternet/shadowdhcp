# Installation on Alpine Linux using Shadow Internet Repository

This guide covers installing `shadowdhcp` on a fresh Alpine installation using the binaries hosted by Shadow Internet.

All commands below should be run as root, or prefixed with `doas`.

## 1. Network requirements

`shadowdhcp` requires at least one IPv4 address and one IPv6 address.
The IPv4 and IPv6 addresses can be on different interfaces; the DHCPv4 and DHCPv6 relays will send requests to these addresses respectively.
RFC1918 addresses can be used for IPv4. A global IPv6 address should be present.

The firewall should allow port 67 and port 547 from the DHCP relays to Alpine.

## 2. Add Shadow Internet repository

> [!NOTE]
> The Shadow Internet Alpine repository is only available over IPv6

```bash
# Install Shadow Internet public key
wget -O /etc/apk/keys/shadowinternet.rsa.pub \
    https://apk.shadowinter.net/keys/shadowinternet.rsa.pub

# Add repository
echo "https://apk.shadowinter.net/stable" >> /etc/apk/repositories

# Install packages
apk update
apk add shadowdhcp
```

## 3. Configuration

Configuration files are stored in `/etc/shadowdhcp/`

There are three configuration files:

* `ids.json` - stores the DHCP server IDs, requires restart on change
* `config.json` - server-wide configuration, requires restart on change
* `reservations.json` - stores reservations, can be hot reloaded

### ids.json

The `apk` installation will attempt to generate server IDs based on the IPv4 address and MAC address of the first interface with a non-localhost IPv4 address.

Check `/etc/shadowdhcp/ids.json` for something similar to the following, or set the IDs as you see fit:

```bash
dhcp:~# cat /etc/shadowdhcp/ids.json
{
        "v4": "10.0.11.19",
        "v6": "00:03:00:01:11:22:33:44:55:66"
}
```

`v4`: IPv4 Address
`v6`: DUID

### config.json

See [configuration](configuration.md) for details on all configuration options. Below is a minimal config:

```json
{
  "dns_v4": ["8.8.8.8", "8.8.4.4"],
  "subnets_v4": [
    {
      "net": "100.100.1.0/24",
      "gateway": "100.100.1.1"
    }
  ]
}
```

### reservations.json

See [reservations](reservations.md) for details on specifying reservations. Below is an example:

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
        "mac": "00-11-22-33-44-57"
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

## Service management

Starting and stopping the service:

```bash
service shadowdhcp start
service shadowdhcp stop
service shadowdhcp restart
```

Start the service on boot:

```bash
rc-update add shadowdhcp default
```

Update reservations by editing `reservations.json` and then:

```bash
service shadowdhcp reload
```

Update reservations via the management socket. See [management](management.md).

Logs are stored at `/var/log/shadowdhcp/shadowdhcp.log`

## Updating

Check [Github](https://github.com/shadowinternet/shadowdhcp) for release notes or breaking changes, then run: `apk upgrade`

## Recommended extras

Install `logrotate` to prevent disk exhaustion from logs, and `vector` for sending events to a database like ClickHouse.

### Logrotate

```
apk add logrotate

cat <<EOF > /etc/logrotate.d/shadowdhcp
/var/log/shadowdhcp/shadowdhcp.log {
    size 10M
    rotate 3
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
```

### Vector

See [events](events.md).