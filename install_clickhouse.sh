#!/usr/bin/env bash
# install_clickhouse.sh
#
# Installs and configures ClickHouse on Debian 13 (trixie) with automatic TLS
# certificates from Let's Encrypt using ClickHouse's built-in ACME client
# (available in 25.11+). Designed for a Proxmox LXC container with a public
# IPv4 OR IPv6 address.
#
# MUST be run as root (or with sudo) on Debian 13.
# REQUIRES a public IPv4 or public IPv6 reachable on port 80 (for the ACME
# HTTP-01 challenge) and on port 443 / 9440 (for encrypted client traffic).
#
# What this does:
#   * Installs ClickHouse from the official apt repository (stable channel)
#   * Enables the embedded clickhouse-keeper (ACME state is stored in Keeper)
#   * Configures the built-in ACME client to obtain & auto-renew a Let's
#     Encrypt certificate via HTTP-01 on port 80
#   * Exposes encrypted endpoints for queries:
#       - https_port       443   (HTTPS interface)
#       - tcp_port_secure  9440  (native TLS protocol)
#     Plain tcp_port (9000) is disabled. http_port (80) is KEPT because the
#     ACME HTTP-01 challenge requires it. Important caveats:
#       - ClickHouse has no per-port ACL, so :80 will also accept authenticated
#         HTTP queries. Any client that accidentally sends a password over
#         http:// leaks it in plaintext. Tell all clients to use https:// or
#         :9440 only.
#       - The script prompts for allowed client IPv4/IPv6 CIDRs and pins the
#         admin user's <networks> to that allowlist, so public scanners
#         (including those probing :80) cannot authenticate even if they try.
#   * Creates an admin SQL user with a password and a network allowlist
#     (IPv4/IPv6 CIDRs) supplied at prompt
#   * Applies ClickHouse's recommended Linux tuning (sysctl, ulimits, THP)
#
# Why built-in ACME (instead of certbot / acme.sh / lego):
#   ClickHouse 25.11 ships its own ACME client, so there is nothing to add or
#   update separately -- renewals are handled by the ClickHouse process and the
#   cert lives in Keeper. If you ever need to fall back to a third party client
#   on Debian, `certbot` (package: certbot) is in the Debian main repo and is
#   the simplest choice for --standalone renewals.

set -euo pipefail

#############################################
# Helpers
#############################################
log()  { printf '\e[1;32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33m[!]\e[0m %s\n' "$*" >&2; }
err()  { printf '\e[1;31m[x]\e[0m %s\n' "$*" >&2; exit 1; }

ask() {
    local prompt="$1" default="${2:-}" answer
    if [[ -n "$default" ]]; then
        read -r -p "$prompt [$default]: " answer || true
        printf '%s' "${answer:-$default}"
    else
        read -r -p "$prompt: " answer || true
        printf '%s' "$answer"
    fi
}

ask_secret() {
    # Stdout is usually captured by the caller with $(...), so the terminal
    # newline echoes after each silent `read` must go to stderr or they get
    # swallowed and every prompt prints on the same line.
    local prompt="$1" s1 s2
    while true; do
        read -r -s -p "$prompt: " s1; printf '\n' >&2
        read -r -s -p "$prompt (confirm): " s2; printf '\n' >&2
        if [[ "$s1" == "$s2" && -n "$s1" ]]; then
            printf '%s' "$s1"
            return 0
        fi
        warn "Passwords did not match or were empty. Try again."
    done
}

ask_secret_optional() {
    # Same as ask_secret, but accepts an empty answer (returns empty string).
    local prompt="$1" s1 s2
    while true; do
        read -r -s -p "$prompt: " s1; printf '\n' >&2
        if [[ -z "$s1" ]]; then
            return 0
        fi
        read -r -s -p "$prompt (confirm): " s2; printf '\n' >&2
        if [[ "$s1" == "$s2" ]]; then
            printf '%s' "$s1"
            return 0
        fi
        warn "Passwords did not match. Try again."
    done
}

require_root() {
    [[ $EUID -eq 0 ]] || err "Please run this script as root (sudo $0)."
}

require_debian13() {
    [[ -f /etc/os-release ]] || err "/etc/os-release missing; not a supported system."
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ "${ID:-}" != "debian" ]]; then
        warn "This script targets Debian 13. Detected ID=$ID. Continuing anyway."
    fi
    if [[ "${VERSION_ID:-}" != "13" ]]; then
        warn "This script targets Debian 13 (trixie). Detected VERSION_ID=${VERSION_ID:-?}. Continuing anyway."
    fi
}

#############################################
# Preflight
#############################################
require_root
require_debian13

log "Gathering configuration. Press Ctrl-C to abort."
echo

DOMAIN="$(ask 'Fully qualified domain name for this server (e.g. clickhouse.example.com)')"
[[ -n "$DOMAIN" ]] || err "Domain is required."

LE_EMAIL="$(ask 'Email address for Let'\''s Encrypt expiry notices')"
[[ -n "$LE_EMAIL" ]] || err "Email is required."

TOS_OK="$(ask 'Do you agree to the Let'\''s Encrypt Terms of Service? (yes/no)' 'yes')"
[[ "$TOS_OK" == "yes" ]] || err "You must agree to Let's Encrypt ToS to continue."

ADMIN_USER="$(ask 'ClickHouse admin username' 'admin')"
ADMIN_PASSWORD="$(ask_secret 'ClickHouse admin password')"
DEFAULT_PASSWORD="$(ask_secret_optional 'Password for the built-in `default` user (press Enter to auto-generate; this user is locked to localhost and you should never need to log in as it)')"
if [[ -z "$DEFAULT_PASSWORD" ]]; then
    DEFAULT_PASSWORD="$(head -c 32 /dev/urandom | base64 | tr -d '=+/' | head -c 32)"
    log "Auto-generated a random password for the 'default' user."
fi

LISTEN_HOST="$(ask 'listen_host for ClickHouse (use :: for dual-stack IPv4+IPv6, or 0.0.0.0 / a specific IP)' '::')"

echo
echo "Network allowlist for the admin user. ClickHouse <networks> ACLs are"
echo "per-user across ALL ports (including :80), so pinning the admin to your"
echo "real client subnets is the main defence against scanners probing :80."
echo "Enter comma-separated CIDRs. Leave BOTH blank to lock admin to localhost."
echo
ADMIN_IPV4_CIDRS="$(ask 'Allowed IPv4 CIDRs for admin user (e.g. 10.0.0.0/8,203.0.113.5/32)' '')"
ADMIN_IPV6_CIDRS="$(ask 'Allowed IPv6 CIDRs for admin user (e.g. 2001:db8::/32)'            '')"

CHANNEL="$(ask 'ClickHouse apt channel (stable or lts; stable is required for ACME 25.11+)' 'stable')"

# Normalise the allowlist. If the user left both blank, lock admin down to
# localhost (safer default than ::/0).
if [[ -z "$ADMIN_IPV4_CIDRS" && -z "$ADMIN_IPV6_CIDRS" ]]; then
    warn "No CIDRs provided; admin user will be restricted to localhost only."
    warn "You will need to SSH into this container and run clickhouse-client"
    warn "locally, or edit /etc/clickhouse-server/users.d/00-admin.xml later"
    warn "to allow remote clients."
    ADMIN_IPV4_CIDRS="127.0.0.1/32"
    ADMIN_IPV6_CIDRS="::1/128"
fi

echo
log "Summary"
echo "  Domain:         $DOMAIN"
echo "  LE email:       $LE_EMAIL"
echo "  Admin user:     $ADMIN_USER"
echo "  Admin IPv4:     ${ADMIN_IPV4_CIDRS:-<none>}"
echo "  Admin IPv6:     ${ADMIN_IPV6_CIDRS:-<none>}"
echo "  listen_host:    $LISTEN_HOST"
echo "  apt channel:    $CHANNEL"
echo
CONFIRM="$(ask 'Proceed with install? (yes/no)' 'yes')"
[[ "$CONFIRM" == "yes" ]] || err "Aborted by user."

#############################################
# OS prep and tuning
#############################################
log "Installing prerequisite packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y \
    apt-transport-https ca-certificates curl gnupg \
    dirmngr lsb-release tzdata dnsutils

# In an LXC container, most vm.*/fs.*/kernel.* sysctls and the THP knobs
# live in the host's /proc/sys and are read-only from inside. Detect that
# and guide the operator to apply host-level settings on the Proxmox host.
IN_CONTAINER=0
if command -v systemd-detect-virt >/dev/null 2>&1 \
    && systemd-detect-virt --container --quiet; then
    IN_CONTAINER=1
fi

# Split the settings into two files: one with namespaced (container-safe)
# settings that we apply live, and one with host-level settings that we only
# write for reference (and apply directly on bare metal / VMs).
log "Writing ClickHouse-recommended kernel tuning"
cat >/etc/sysctl.d/99-clickhouse-container.conf <<'EOF'
# ClickHouse: namespaced sysctls safe to apply inside a container.
net.core.somaxconn              = 65535
net.core.netdev_max_backlog     = 65535
net.ipv4.tcp_max_syn_backlog    = 65535
net.ipv4.tcp_fin_timeout        = 15
net.ipv4.tcp_tw_reuse           = 1
EOF

cat >/etc/sysctl.d/99-clickhouse-host.conf <<'EOF'
# ClickHouse: host-level kernel tuning. These CANNOT be set from inside an
# LXC container -- apply this file on the Proxmox HOST (`sysctl --system`).
# See https://clickhouse.com/docs/operations/tips
vm.max_map_count        = 262144
vm.swappiness           = 1
vm.overcommit_memory    = 1
fs.file-max             = 2097152
fs.aio-max-nr           = 1048576
kernel.threads-max      = 120000
kernel.task_delayacct   = 1
EOF

# Apply the container-safe file. Use `-e` so an unknown key (e.g. on a
# non-Linux kernel) is a warning, not a fatal error.
sysctl -e -p /etc/sysctl.d/99-clickhouse-container.conf >/dev/null

if (( IN_CONTAINER )); then
    # Try the host-level file too -- harmless if it fails, and on privileged
    # LXCs with appropriate caps some of these might actually succeed.
    sysctl -e -p /etc/sysctl.d/99-clickhouse-host.conf >/dev/null 2>&1 || true
    warn "Running inside a container: the host-level kernel tunables listed in"
    warn "/etc/sysctl.d/99-clickhouse-host.conf could not be applied from here."
    warn "On the Proxmox HOST, copy that file to /etc/sysctl.d/ and run:"
    warn "    sudo sysctl --system"
    warn "Key values: vm.max_map_count=262144, fs.file-max=2097152,"
    warn "            vm.swappiness=1, vm.overcommit_memory=1"
else
    sysctl -e -p /etc/sysctl.d/99-clickhouse-host.conf >/dev/null
fi

if (( IN_CONTAINER )); then
    warn "Skipping Transparent Huge Pages service: THP is a host-level knob."
    warn "On the Proxmox HOST, set THP to 'madvise' for best ClickHouse perf:"
    warn "    echo madvise > /sys/kernel/mm/transparent_hugepage/enabled"
    warn "    echo madvise > /sys/kernel/mm/transparent_hugepage/defrag"
    warn "(Persist via a systemd unit or /etc/rc.local on the host.)"
else
    log "Setting Transparent Huge Pages to madvise (persistent)"
    cat >/etc/systemd/system/disable-thp.service <<'EOF'
[Unit]
Description=Set THP to madvise for ClickHouse
DefaultDependencies=no
After=sysinit.target local-fs.target
Before=clickhouse-server.service

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo madvise > /sys/kernel/mm/transparent_hugepage/enabled && echo madvise > /sys/kernel/mm/transparent_hugepage/defrag'
RemainAfterExit=yes

[Install]
WantedBy=basic.target
EOF
    systemctl daemon-reload
    systemctl enable --now disable-thp.service
fi

#############################################
# ClickHouse install
#############################################
log "Adding ClickHouse apt repository ($CHANNEL channel)"
install -d -m 0755 /usr/share/keyrings
curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' \
    | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg

ARCH="$(dpkg --print-architecture)"
cat >/etc/apt/sources.list.d/clickhouse.list <<EOF
deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=$ARCH] https://packages.clickhouse.com/deb $CHANNEL main
EOF
apt-get update -y

log "Pre-seeding default-user password so the installer does not prompt"
# The clickhouse-server package reads this env var during its post-install.
export CLICKHOUSE_SKIP_USER_SETUP=1

log "Installing clickhouse-server and clickhouse-client"
apt-get install -y clickhouse-server clickhouse-client

CH_VERSION="$(dpkg-query -W -f='${Version}\n' clickhouse-server)"
log "Installed clickhouse-server $CH_VERSION"

# ACME is 25.11+; warn if older.
CH_MAJOR="$(printf '%s\n' "$CH_VERSION" | cut -d. -f1)"
CH_MINOR="$(printf '%s\n' "$CH_VERSION" | cut -d. -f2)"
if (( CH_MAJOR < 25 )) || { (( CH_MAJOR == 25 )) && (( CH_MINOR < 11 )); }; then
    err "clickhouse-server $CH_VERSION is older than 25.11 which introduced the built-in ACME client. Use the 'stable' channel or pin a newer version and re-run."
fi

#############################################
# systemd overrides (ulimits + bind to <1024)
#############################################
log "Applying systemd overrides (ulimits, bind <1024, hardening)"
install -d -m 0755 /etc/systemd/system/clickhouse-server.service.d
# The upstream ClickHouse unit already sets CapabilityBoundingSet and
# AmbientCapabilities with the four caps it needs (CAP_NET_ADMIN,
# CAP_IPC_LOCK, CAP_SYS_NICE, CAP_NET_BIND_SERVICE), so we do NOT redefine
# them -- a drop-in would replace the upstream list rather than extend it.
cat >/etc/systemd/system/clickhouse-server.service.d/override.conf <<'EOF'
[Service]
LimitNOFILE=1048576
LimitNPROC=infinity
TasksMax=infinity
EOF
systemctl daemon-reload

#############################################
# ClickHouse configuration
#############################################
CONF_D=/etc/clickhouse-server/config.d
USERS_D=/etc/clickhouse-server/users.d
install -d -m 0755 -o clickhouse -g clickhouse "$CONF_D" "$USERS_D"
install -d -m 0750 -o clickhouse -g clickhouse /var/lib/clickhouse/coordination

# 00-network.xml: disable plain ports, enable encrypted ones.
# http_port 80 is KEPT because the ACME HTTP-01 challenge needs it.
# The `remove="1"` attribute tells ClickHouse to delete the matching default
# from config.xml so we genuinely do not listen on those ports.
log "Writing network config ($CONF_D/00-network.xml)"
cat >"$CONF_D/00-network.xml" <<EOF
<clickhouse>
    <listen_host>$LISTEN_HOST</listen_host>
    <listen_try>true</listen_try>

    <!-- HTTP-01 challenge endpoint (Let's Encrypt reaches us here). -->
    <http_port>80</http_port>

    <!-- Encrypted endpoints: the only ports clients should use for queries. -->
    <https_port>443</https_port>
    <tcp_port_secure>9440</tcp_port_secure>

    <!-- Remove plaintext defaults from config.xml so we don't listen on them. -->
    <tcp_port remove="1"/>
    <mysql_port remove="1"/>
    <postgresql_port remove="1"/>
    <interserver_http_port remove="1"/>

    <max_connections>4096</max_connections>
    <keep_alive_timeout>10</keep_alive_timeout>
</clickhouse>
EOF

# 10-keeper.xml: embedded clickhouse-keeper (required by the ACME feature --
# account key + issued cert live in Keeper's /clickhouse/acme path).
log "Writing embedded Keeper config ($CONF_D/10-keeper.xml)"
cat >"$CONF_D/10-keeper.xml" <<'EOF'
<clickhouse>
    <keeper_server>
        <tcp_port>9181</tcp_port>
        <server_id>1</server_id>
        <log_storage_path>/var/lib/clickhouse/coordination/log</log_storage_path>
        <snapshot_storage_path>/var/lib/clickhouse/coordination/snapshots</snapshot_storage_path>
        <coordination_settings>
            <operation_timeout_ms>10000</operation_timeout_ms>
            <session_timeout_ms>30000</session_timeout_ms>
            <raft_logs_level>warning</raft_logs_level>
        </coordination_settings>
        <raft_configuration>
            <server>
                <id>1</id>
                <hostname>localhost</hostname>
                <port>9234</port>
            </server>
        </raft_configuration>
    </keeper_server>

    <!-- Point ClickHouse itself at the embedded Keeper instance. -->
    <zookeeper>
        <node>
            <host>localhost</host>
            <port>9181</port>
        </node>
    </zookeeper>
</clickhouse>
EOF

# 20-acme.xml: the built-in ACME client.
log "Writing ACME config ($CONF_D/20-acme.xml)"
cat >"$CONF_D/20-acme.xml" <<EOF
<clickhouse>
    <acme>
        <!-- Let's Encrypt (default directory). Set <directory_url> to point
             at a different CA if you ever need to (ZeroSSL, staging, etc.). -->
        <email>$LE_EMAIL</email>
        <terms_of_service_agreed>true</terms_of_service_agreed>
        <!-- Where the account key and issued certs are stored inside Keeper. -->
        <zookeeper_path>/clickhouse/acme</zookeeper_path>
        <domains>
            <domain>$DOMAIN</domain>
        </domains>
    </acme>
</clickhouse>
EOF

# 30-openssl.xml: strong TLS only (TLS 1.2 + TLS 1.3), tie into ACME-issued
# material. The openSSL.server section is what ClickHouse's TLS endpoints
# consult; when ACME is enabled the built-in client writes the issued
# certificate into this live config.
log "Writing OpenSSL / TLS policy ($CONF_D/30-openssl.xml)"
cat >"$CONF_D/30-openssl.xml" <<'EOF'
<clickhouse>
    <openSSL>
        <server>
            <!-- NOTE: do NOT declare certificateFile / privateKeyFile here.
                 When the ACME provider is enabled (see 20-acme.xml), ClickHouse
                 rejects startup with "Static TLS keys and ACME provider are
                 enabled at the same time" if static paths are present. The
                 ACME client injects the issued key + cert into the live TLS
                 context once Let's Encrypt completes HTTP-01 validation. -->
            <dhParamsFile></dhParamsFile>
            <verificationMode>none</verificationMode>
            <loadDefaultCAFile>true</loadDefaultCAFile>
            <cacheSessions>true</cacheSessions>
            <disableProtocols>sslv2,sslv3,tlsv1,tlsv1_1</disableProtocols>
            <preferServerCiphers>true</preferServerCiphers>
            <!-- Modern cipher suites only. TLS 1.3 ciphers are negotiated automatically. -->
            <cipherList>ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256</cipherList>
        </server>
        <client>
            <loadDefaultCAFile>true</loadDefaultCAFile>
            <cacheSessions>true</cacheSessions>
            <disableProtocols>sslv2,sslv3,tlsv1,tlsv1_1</disableProtocols>
            <preferServerCiphers>true</preferServerCiphers>
            <invalidCertificateHandler>
                <name>RejectCertificateHandler</name>
            </invalidCertificateHandler>
        </client>
    </openSSL>
</clickhouse>
EOF
install -d -m 0750 -o clickhouse -g clickhouse /var/lib/clickhouse/acme

#############################################
# Users
#############################################
# SHA256-hex the passwords the way ClickHouse's users.xml expects.
sha256_hex() { printf '%s' "$1" | sha256sum | awk '{print $1}'; }
ADMIN_HASH="$(sha256_hex "$ADMIN_PASSWORD")"
DEFAULT_HASH="$(sha256_hex "$DEFAULT_PASSWORD")"

log "Writing admin user and locking down 'default' ($USERS_D/)"
# ClickHouse <networks> is per-user across ALL ports (including :80). Pinning
# the admin to the operator's real client CIDRs means a scanner probing :80
# cannot authenticate even if it could reach the port.

# Emit <ip>CIDR</ip> entries (one per line) from a comma-separated input.
emit_networks() {
    local csv="$1" indent="$2" cidr IFS=','
    for cidr in $csv; do
        cidr="${cidr// /}"
        [[ -z "$cidr" ]] && continue
        printf '%s<ip>%s</ip>\n' "$indent" "$cidr"
    done
}

{
    cat <<EOF
<clickhouse>
    <users>
        <$ADMIN_USER>
            <password_sha256_hex>$ADMIN_HASH</password_sha256_hex>
            <networks>
                <!-- Loopback is always allowed so you can admin from the
                     server itself (clickhouse-client --host 127.0.0.1 / ::1). -->
                <ip>::1</ip>
                <ip>127.0.0.1</ip>
EOF
    emit_networks "$ADMIN_IPV4_CIDRS" '                '
    emit_networks "$ADMIN_IPV6_CIDRS" '                '
    cat <<EOF
            </networks>
            <profile>default</profile>
            <quota>default</quota>
            <access_management>1</access_management>
            <named_collection_control>1</named_collection_control>
            <show_named_collections>1</show_named_collections>
            <show_named_collections_secrets>1</show_named_collections_secrets>
        </$ADMIN_USER>
        <!-- replace="1" so our definition overwrites the base users.xml
             default user (which ships with an empty <password></password>
             element). Without this, ClickHouse sees both <password> and
             <password_sha256_hex> on the merged user and refuses to start
             with "More than one field ... used to specify authentication". -->
        <default replace="1">
            <password_sha256_hex>$DEFAULT_HASH</password_sha256_hex>
            <networks>
                <ip>::1</ip>
                <ip>127.0.0.1</ip>
            </networks>
            <profile>default</profile>
            <quota>default</quota>
        </default>
    </users>
</clickhouse>
EOF
} >"$USERS_D/00-admin.xml"

cat >"$USERS_D/10-profiles.xml" <<'EOF'
<clickhouse>
    <profiles>
        <default>
            <max_memory_usage>10000000000</max_memory_usage>
            <use_uncompressed_cache>0</use_uncompressed_cache>
            <load_balancing>random</load_balancing>
            <prefer_global_in_and_join>0</prefer_global_in_and_join>
        </default>
    </profiles>

    <quotas>
        <default>
            <interval>
                <duration>3600</duration>
                <queries>0</queries>
                <errors>0</errors>
                <result_rows>0</result_rows>
                <read_rows>0</read_rows>
                <execution_time>0</execution_time>
            </interval>
        </default>
    </quotas>
</clickhouse>
EOF

chown -R clickhouse:clickhouse "$CONF_D" "$USERS_D"
find "$CONF_D" "$USERS_D" -type f -exec chmod 0640 {} \;

#############################################
# Start ClickHouse
# (Firewall rules are NOT configured by this script -- configure your Proxmox
# datacenter / node / container firewall using the port summary at the end.)
#############################################
log "Enabling and starting clickhouse-server"
systemctl enable clickhouse-server
systemctl restart clickhouse-server

log "Waiting up to 120s for ClickHouse to open its TLS port and for ACME to issue a certificate"
for i in $(seq 1 24); do
    if ss -H -ltn 'sport = :9440' | grep -q LISTEN; then
        log "tcp_port_secure (9440) is listening"
        break
    fi
    sleep 5
done

#############################################
# Final verification
#############################################
echo
log "Install complete. Quick verification:"
echo
echo "  - Check the server log for ACME progress:"
echo "      journalctl -u clickhouse-server -n 200 --no-pager | grep -iE 'acme|ssl|certificate'"
echo
echo "  - Test the HTTPS interface from another host:"
echo "      curl -v https://$DOMAIN/ping"
echo
echo "  - Test the native TLS protocol:"
echo "      clickhouse-client --host $DOMAIN --port 9440 --secure \\"
echo "          --user $ADMIN_USER --password --query 'SELECT version()'"
echo
echo "  - Certificate + key (once issued) live under:"
echo "      /var/lib/clickhouse/acme/   (populated by the built-in ACME client)"
echo "      Keeper path: /clickhouse/acme"
echo
cat <<EOF
================================================================================
 FIREWALL: configure your Proxmox (datacenter / node / container) firewall.
 This script did NOT open any ports. The ClickHouse server is listening on:

   Port     Proto   Purpose                          Who should reach it
   ------   -----   ------------------------------   -----------------------------
   80       tcp     ACME HTTP-01 challenge           PUBLIC (Internet)
                                                     Required so Let's Encrypt
                                                     can validate $DOMAIN.
   443      tcp     HTTPS query interface            Your ClickHouse clients
                                                     (apps, BI tools, curl, etc.)
   9440     tcp     Native ClickHouse protocol/TLS   Your ClickHouse clients
                                                     using clickhouse-client or
                                                     a native driver over TLS.
   9181     tcp     Embedded clickhouse-keeper       LOCALHOST ONLY -- do NOT
                                                     expose; only this server
                                                     uses it for ACME state.
   22       tcp     SSH (if you use it)              Your admin subnet / VPN.

 NOT listening (removed via <remove=\"1\"/> in 00-network.xml):
   9000 (plaintext native), 9004 (MySQL), 9005 (Postgres), 9009 (interserver HTTP)

 Minimum rule set for a single-node install on the public IPv4/IPv6:
   allow inbound 80/tcp, 443/tcp, 9440/tcp from the Internet
   allow inbound 22/tcp from your admin network
   deny  inbound 9181/tcp from anywhere except 127.0.0.1 / ::1

 Note: port 80 is required year-round, not just during issuance -- the built-in
 ACME client renews certs ~30 days before expiry and needs HTTP-01 to succeed.
 ClickHouse also serves its plain HTTP query interface on port 80, so do NOT
 send queries to http://$DOMAIN/ -- use https://$DOMAIN/ or :9440 only.
================================================================================

 ADMIN USER NETWORK ALLOWLIST
 ----------------------------
 The '$ADMIN_USER' user is pinned to these CIDRs (requests from anywhere else
 are rejected at authentication, on every port):

   IPv4: ${ADMIN_IPV4_CIDRS:-<none>}
   IPv6: ${ADMIN_IPV6_CIDRS:-<none>}

 To edit the allowlist later, modify /etc/clickhouse-server/users.d/00-admin.xml
 under the <$ADMIN_USER> element. Each allowed range is one child tag inside
 <networks>, e.g.:

   <clickhouse>
     <users>
       <$ADMIN_USER>
         <networks>
           <ip>10.0.0.0/8</ip>                  <!-- office LAN -->
           <ip>203.0.113.5/32</ip>              <!-- build server -->
           <ip>2001:db8:abcd::/48</ip>          <!-- VPN v6 range -->
           <host_regexp>.*\\.corp\\.example\\.com</host_regexp>
         </networks>
       </$ADMIN_USER>
     </users>
   </clickhouse>

 Accepted match tags (per ClickHouse docs):
   <ip>           single address or CIDR, IPv4 or IPv6
   <host>         exact DNS hostname (reverse-lookup must match)
   <host_regexp>  regex matched against the reverse DNS name

 After editing, ClickHouse auto-detects changes in users.d/ and picks them up
 within a few seconds -- no restart required. If you want to force an immediate
 reload:
   sudo clickhouse-client --query 'SYSTEM RELOAD USERS'

 To verify who the server currently trusts:
   clickhouse-client --query \"SELECT name, host_ip, host_names FROM system.users WHERE name = '$ADMIN_USER'\"

================================================================================
EOF
