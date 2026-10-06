-- ClickHouse schema for shadowdhcp analytics
-- Run with (as your admin user, from a machine in the admin allowlist):
--   clickhouse-client --host <server> --port 9440 --secure \
--                     --user admin --password --multiquery < clickhouse_schema.sql

-- =============================================================================
-- Creating a restricted 'dhcp_writer' user
-- =============================================================================
-- The DHCP server(s) only INSERT rows into the events tables, so the writer
-- account gets INSERT and nothing else. Without SELECT, a leaked writer
-- credential can't read subscriber data (MACs, Option 82/18/37 identifiers)
-- back out. The snippet below creates a user that:
--   * authenticates with a password (bcrypt-hashed on disk)
--   * can INSERT into any table in the dhcp.* database
--   * CANNOT SELECT, ALTER, DROP, or access any other database
--   * can only connect from the IP ranges you list
--
-- Connect as an admin user (one with access_management = 1) and run:
--
--   CREATE USER dhcp_writer
--       IDENTIFIED WITH bcrypt_password BY 'REPLACE_WITH_STRONG_PASSWORD'
--       HOST IP '2001:db8:abcd::/48',   -- v6 subnet your DHCP servers live on
--            IP '10.20.30.0/24';        -- v4 subnet (optional; list as many as needed)
--
--   GRANT INSERT ON dhcp.* TO dhcp_writer;
--
-- Useful follow-ups:
--   SHOW GRANTS FOR dhcp_writer;
--   ALTER USER dhcp_writer IDENTIFIED WITH bcrypt_password BY 'new-password';
--   ALTER USER dhcp_writer HOST IP '2001:db8:abcd::/48', IP '10.20.30.0/24';
--   DROP USER dhcp_writer;
--
-- Connect test from a DHCP server inside the allowlist:
--   clickhouse-client --host <server> --port 9440 --secure \
--                     --user dhcp_writer --password \
--                     --query "INSERT INTO dhcp.events_v4 (timestamp, success) VALUES (toUnixTimestamp64Milli(now64(3)), 1)"
-- =============================================================================

CREATE DATABASE IF NOT EXISTS dhcp;

-- DHCPv4 events table
CREATE TABLE IF NOT EXISTS dhcp.events_v4
(
    -- Timing. shadowdhcp sends `timestamp` as integer Unix milliseconds and
    -- event_time converts it explicitly. Don't insert the integer straight
    -- into a DateTime64 column: ClickHouse 26.8 reads a bare integer as
    -- seconds regardless of precision and clamps every row to the max date.
    timestamp Int64 CODEC(Delta, ZSTD),
    event_time DateTime64(3) DEFAULT fromUnixTimestamp64Milli(timestamp) CODEC(Delta, ZSTD),

    -- Server identification
    host_name LowCardinality(String) DEFAULT '',

    -- Message info
    message_type LowCardinality(Nullable(String)),
    relay_addr IPv4,

    -- Request data (from client/relay)
    mac_address Nullable(String),
    option82_circuit Nullable(String),
    option82_remote Nullable(String),
    option82_subscriber Nullable(String),

    -- Reservation data (what matched)
    reservation_ipv4 Nullable(IPv4),
    reservation_mac Nullable(String),
    reservation_option82_circuit Nullable(String),
    reservation_option82_remote Nullable(String),
    reservation_option82_subscriber Nullable(String),

    -- Match info (how was reservation found)
    match_method LowCardinality(Nullable(String)),  -- 'mac', 'option82'
    extractor_used LowCardinality(Nullable(String)),  -- extractor name (e.g., 'chaddr' for mac, or option82 extractor name)

    -- Result
    success UInt8,
    failure_reason LowCardinality(Nullable(String)),

    -- Indices.
    -- match_method is LowCardinality with ~5 distinct values, so a bloom
    -- filter would be redundant — LowCardinality already gives constant-time
    -- equality filtering. Same goes for message_type / extractor_used /
    -- failure_reason; query them directly without a skip index. host_name
    -- leads the ORDER BY key, so it needs no skip index either.
    INDEX idx_mac mac_address TYPE bloom_filter GRANULARITY 4,
    INDEX idx_reservation_ipv4 reservation_ipv4 TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(event_time)
ORDER BY (host_name, relay_addr, event_time)
TTL event_time + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- DHCPv6 events table
CREATE TABLE IF NOT EXISTS dhcp.events_v6
(
    -- Timing. shadowdhcp sends `timestamp` as integer Unix milliseconds and
    -- event_time converts it explicitly. Don't insert the integer straight
    -- into a DateTime64 column: ClickHouse 26.8 reads a bare integer as
    -- seconds regardless of precision and clamps every row to the max date.
    timestamp Int64 CODEC(Delta, ZSTD),
    event_time DateTime64(3) DEFAULT fromUnixTimestamp64Milli(timestamp) CODEC(Delta, ZSTD),

    -- Server identification
    host_name LowCardinality(String) DEFAULT '',

    -- Message info
    message_type LowCardinality(String),
    xid FixedString(6),  -- DHCPv6 transaction id is exactly 3 bytes (RFC 8415); writer emits 6-char hex
    relay_addr IPv6,
    relay_link_addr IPv6,
    relay_peer_addr IPv6,

    -- Request data (from client/relay)
    mac_address Nullable(String),
    client_id Nullable(String),
    option1837_interface Nullable(String),
    option1837_remote Nullable(String),
    requested_ipv6_na Nullable(IPv6),
    requested_ipv6_pd_prefix Nullable(IPv6),
    requested_ipv6_pd_length Nullable(UInt8),

    -- Reservation data (what matched)
    reservation_ipv6_na Nullable(IPv6),
    reservation_ipv6_pd_prefix Nullable(IPv6),
    reservation_ipv6_pd_length Nullable(UInt8),
    reservation_ipv4 Nullable(IPv4),
    reservation_mac Nullable(String),
    reservation_duid Nullable(String),
    reservation_option1837_interface Nullable(String),
    reservation_option1837_remote Nullable(String),

    -- Match info (how was reservation found)
    match_method LowCardinality(Nullable(String)),  -- 'mac', 'duid', 'option1837', 'option82'
    extractor_used LowCardinality(Nullable(String)),  -- extractor name (mac: 'client_linklayer_address', 'peer_addr_eui64', 'duid'; option1837/option82: extractor name)

    -- Result
    success UInt8,
    failure_reason LowCardinality(Nullable(String)),

    -- Indices. As with events_v4, no bloom filter on match_method /
    -- extractor_used / message_type — LowCardinality already covers them.
    INDEX idx_mac mac_address TYPE bloom_filter GRANULARITY 4,
    INDEX idx_client_id client_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_reservation_ipv6_na reservation_ipv6_na TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(event_time)
ORDER BY (host_name, relay_addr, event_time)
TTL event_time + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Example queries:

-- Most frequent DHCP clients (v4)
-- SELECT mac_address, count() as total FROM dhcp.events_v4 WHERE mac_address IS NOT NULL GROUP BY mac_address ORDER BY total DESC LIMIT 10;

-- Clients that tried to get an address without a reservation
-- SELECT * FROM dhcp.events_v4 WHERE success = 0 AND failure_reason = 'NoReservation' ORDER BY event_time DESC LIMIT 100;
-- SELECT * FROM dhcp.events_v6 WHERE success = 0 AND failure_reason = 'NoReservation' ORDER BY event_time DESC LIMIT 100;

-- Total successful requests today
-- SELECT count() FROM dhcp.events_v4 WHERE success = 1 AND event_time >= today();
-- SELECT count() FROM dhcp.events_v6 WHERE success = 1 AND event_time >= today();

-- Clients with v4 address but no v6 (using reservation_ipv4 correlation)
-- SELECT DISTINCT e4.mac_address, e4.reservation_ipv4
-- FROM dhcp.events_v4 e4
-- LEFT JOIN dhcp.events_v6 e6 ON e4.mac_address = e6.mac_address AND e6.success = 1
-- WHERE e4.success = 1 AND e4.mac_address IS NOT NULL AND e6.mac_address IS NULL;

-- Requests by relay
-- SELECT relay_addr, count() as total FROM dhcp.events_v4 GROUP BY relay_addr ORDER BY total DESC;

-- Requests by match method (how was reservation found)
-- SELECT match_method, count() as total FROM dhcp.events_v4 WHERE success = 1 GROUP BY match_method;
-- SELECT match_method, count() as total FROM dhcp.events_v6 WHERE success = 1 GROUP BY match_method;

-- Requests matched by Option82 with specific extractor
-- SELECT * FROM dhcp.events_v4 WHERE match_method = 'option82' AND extractor_used = 'remote_only' ORDER BY event_time DESC LIMIT 100;

-- Breakdown by extractor used
-- SELECT extractor_used, count() as total FROM dhcp.events_v4 WHERE match_method = 'option82' GROUP BY extractor_used;
-- SELECT extractor_used, count() as total FROM dhcp.events_v6 WHERE match_method = 'option1837' GROUP BY extractor_used;

-- MAC extractor breakdown (DHCPv6)
-- SELECT extractor_used, count() as total FROM dhcp.events_v6 WHERE match_method = 'mac' GROUP BY extractor_used;
-- Possible values: 'client_linklayer_address' (RFC 6939), 'peer_addr_eui64', 'duid'

-- Events from specific server
-- SELECT * FROM dhcp.events_v4 WHERE host_name = 'dhcp-server-01' ORDER BY event_time DESC LIMIT 100;

-- Request count per server
-- SELECT host_name, count() as total FROM dhcp.events_v4 GROUP BY host_name;

-- Malformed or undeliverable traffic per relay (failure_reason values:
-- 'ParseError' = undecodable datagram; 'NoRelayMsg'/'NestedRelay' = v6 relay
-- wrapper without a usable inner message; 'EncodeFailed'/'SendFailed' = a
-- response was built but never reached the wire)
-- SELECT relay_addr, failure_reason, count() as total FROM dhcp.events_v4 WHERE failure_reason IN ('ParseError', 'EncodeFailed', 'SendFailed') GROUP BY relay_addr, failure_reason;
-- SELECT relay_addr, failure_reason, count() as total FROM dhcp.events_v6 WHERE failure_reason IN ('ParseError', 'NoRelayMsg', 'NestedRelay', 'EncodeFailed', 'SendFailed') GROUP BY relay_addr, failure_reason;
