-- ClickHouse schema for shadowdhcp analytics
-- Run with (as your admin user, from a machine in the admin allowlist):
--   clickhouse-client --host <server> --port 9440 --secure \
--                     --user admin --password --multiquery < clickhouse_schema.sql

-- =============================================================================
-- Creating a restricted 'dhcp_writer' user
-- =============================================================================
-- The DHCP server(s) INSERT rows into the source tables. The materialized
-- views below are populated automatically by ClickHouse, but their SELECTs
-- run *as the inserting user*, so dhcp_writer also needs SELECT on the
-- events tables — otherwise the INSERT fails with ACCESS_DENIED while
-- pushing to the MV. The snippet below creates a user that:
--   * authenticates with a password (bcrypt-hashed on disk)
--   * can INSERT into any table in the dhcp.* database
--   * can SELECT from dhcp.* (needed for the MV push; otherwise unused)
--   * CANNOT ALTER, DROP, or access any other database
--   * can only connect from the IP ranges you list
--
-- Connect as an admin user (one with access_management = 1) and run:
--
--   CREATE USER dhcp_writer
--       IDENTIFIED WITH bcrypt_password BY 'REPLACE_WITH_STRONG_PASSWORD'
--       HOST IP '2001:db8:abcd::/48',   -- v6 subnet your DHCP servers live on
--            IP '10.20.30.0/24';        -- v4 subnet (optional; list as many as needed)
--
--   GRANT INSERT, SELECT ON dhcp.* TO dhcp_writer;
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
--                     --query "INSERT INTO dhcp.events_v4 (timestamp, success) VALUES (now64(3), 1)"
-- =============================================================================

CREATE DATABASE IF NOT EXISTS dhcp;

-- DHCPv4 events table
CREATE TABLE IF NOT EXISTS dhcp.events_v4
(
    -- Timing
    timestamp DateTime64(3),

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
    -- failure_reason; query them directly without a skip index.
    INDEX idx_host host_name TYPE bloom_filter GRANULARITY 4,
    INDEX idx_mac mac_address TYPE bloom_filter GRANULARITY 4,
    INDEX idx_reservation_ipv4 reservation_ipv4 TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (host_name, relay_addr, timestamp)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- DHCPv6 events table
CREATE TABLE IF NOT EXISTS dhcp.events_v6
(
    -- Timing
    timestamp DateTime64(3),

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
    INDEX idx_host host_name TYPE bloom_filter GRANULARITY 4,
    INDEX idx_mac mac_address TYPE bloom_filter GRANULARITY 4,
    INDEX idx_client_id client_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_reservation_ipv6_na reservation_ipv6_na TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (host_name, relay_addr, timestamp)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Materialized views below all aggregate by `message_type` so operators can
-- separate Discover/Request/Renew rates from one another. The source events
-- tables expire at 90 days, but MVs are independent tables that grow until
-- their own TTL fires — set to 365 days here.

-- Materialized view for frequent clients (v4).
-- `mac_address` and `message_type` are nullable in events_v4 (a malformed v4
-- packet may omit option 53), but ORDER BY columns must be non-nullable
-- unless `allow_nullable_key` is on. mac_address rows without a MAC are
-- dropped (they aren't a "client"); message_type nulls are bucketed as
-- 'Unknown' so malformed-packet counts aren't silently lost.
CREATE MATERIALIZED VIEW IF NOT EXISTS dhcp.frequent_clients_v4_mv
ENGINE = SummingMergeTree()
ORDER BY (host_name, mac_address, message_type, date)
TTL date + INTERVAL 365 DAY
AS SELECT
    host_name,
    assumeNotNull(mac_address) AS mac_address,
    ifNull(message_type, 'Unknown') AS message_type,
    toDate(timestamp) AS date,
    count() AS request_count,
    countIf(success = 1) AS success_count,
    countIf(success = 0) AS failure_count
FROM dhcp.events_v4
WHERE mac_address IS NOT NULL
GROUP BY host_name, mac_address, message_type, date;

-- Materialized view for frequent clients (v6)
CREATE MATERIALIZED VIEW IF NOT EXISTS dhcp.frequent_clients_v6_mv
ENGINE = SummingMergeTree()
ORDER BY (host_name, mac_address, message_type, date)
TTL date + INTERVAL 365 DAY
AS SELECT
    host_name,
    assumeNotNull(mac_address) AS mac_address,
    message_type,
    toDate(timestamp) AS date,
    count() AS request_count,
    countIf(success = 1) AS success_count,
    countIf(success = 0) AS failure_count
FROM dhcp.events_v6
WHERE mac_address IS NOT NULL
GROUP BY host_name, mac_address, message_type, date;

-- Materialized view for relay statistics (per host)
-- events_v4.message_type is nullable (see frequent_clients_v4_mv note); bucket
-- nulls as 'Unknown' so the ORDER BY key stays non-nullable.
CREATE MATERIALIZED VIEW IF NOT EXISTS dhcp.relay_stats_v4_mv
ENGINE = SummingMergeTree()
ORDER BY (host_name, relay_addr, message_type, date)
TTL date + INTERVAL 365 DAY
AS SELECT
    host_name,
    relay_addr,
    ifNull(message_type, 'Unknown') AS message_type,
    toDate(timestamp) AS date,
    count() AS request_count,
    countIf(success = 1) AS success_count,
    countIf(success = 0) AS failure_count
FROM dhcp.events_v4
GROUP BY host_name, relay_addr, message_type, date;

CREATE MATERIALIZED VIEW IF NOT EXISTS dhcp.relay_stats_v6_mv
ENGINE = SummingMergeTree()
ORDER BY (host_name, relay_addr, message_type, date)
TTL date + INTERVAL 365 DAY
AS SELECT
    host_name,
    relay_addr,
    message_type,
    toDate(timestamp) AS date,
    count() AS request_count,
    countIf(success = 1) AS success_count,
    countIf(success = 0) AS failure_count
FROM dhcp.events_v6
GROUP BY host_name, relay_addr, message_type, date;

-- Example queries:

-- Most frequent DHCP clients (v4)
-- SELECT mac_address, sum(request_count) as total FROM dhcp.frequent_clients_v4_mv GROUP BY mac_address ORDER BY total DESC LIMIT 10;

-- Clients that tried to get an address without a reservation
-- SELECT * FROM dhcp.events_v4 WHERE success = 0 AND failure_reason = 'NoReservation' ORDER BY timestamp DESC LIMIT 100;
-- SELECT * FROM dhcp.events_v6 WHERE success = 0 AND failure_reason = 'NoReservation' ORDER BY timestamp DESC LIMIT 100;

-- Total successful requests today
-- SELECT count() FROM dhcp.events_v4 WHERE success = 1 AND timestamp >= today();
-- SELECT count() FROM dhcp.events_v6 WHERE success = 1 AND timestamp >= today();

-- Clients with v4 address but no v6 (using reservation_ipv4 correlation)
-- SELECT DISTINCT e4.mac_address, e4.reservation_ipv4
-- FROM dhcp.events_v4 e4
-- LEFT JOIN dhcp.events_v6 e6 ON e4.mac_address = e6.mac_address AND e6.success = 1
-- WHERE e4.success = 1 AND e4.mac_address IS NOT NULL AND e6.mac_address IS NULL;

-- Requests by relay
-- SELECT relay_addr, sum(request_count) as total FROM dhcp.relay_stats_v4_mv GROUP BY relay_addr ORDER BY total DESC;

-- Requests by match method (how was reservation found)
-- SELECT match_method, count() as total FROM dhcp.events_v4 WHERE success = 1 GROUP BY match_method;
-- SELECT match_method, count() as total FROM dhcp.events_v6 WHERE success = 1 GROUP BY match_method;

-- Requests matched by Option82 with specific extractor
-- SELECT * FROM dhcp.events_v4 WHERE match_method = 'option82' AND extractor_used = 'remote_only' ORDER BY timestamp DESC LIMIT 100;

-- Breakdown by extractor used
-- SELECT extractor_used, count() as total FROM dhcp.events_v4 WHERE match_method = 'option82' GROUP BY extractor_used;
-- SELECT extractor_used, count() as total FROM dhcp.events_v6 WHERE match_method = 'option1837' GROUP BY extractor_used;

-- MAC extractor breakdown (DHCPv6)
-- SELECT extractor_used, count() as total FROM dhcp.events_v6 WHERE match_method = 'mac' GROUP BY extractor_used;
-- Possible values: 'client_linklayer_address' (RFC 6939), 'peer_addr_eui64', 'duid'

-- Events from specific server
-- SELECT * FROM dhcp.events_v4 WHERE host_name = 'dhcp-server-01' ORDER BY timestamp DESC LIMIT 100;

-- Request count per server
-- SELECT host_name, sum(request_count) as total FROM dhcp.relay_stats_v4_mv GROUP BY host_name;

-- =============================================================================
-- HyperDX/ClickStack-compatible logs table
-- =============================================================================

-- Schema mirrors the layout the HyperDX UI v2 expects when you create a Source
-- pointing at this table. shadowdhcp inserts directly via JSONEachRow over
-- HTTPS, no OTel collector needed. To use the HyperDX UI, point a Logs Source
-- at `dhcp.otel_logs` and the columns map automatically.
--
-- Reference: https://clickhouse.com/docs/use-cases/observability/clickstack/ingesting-data/schemas
CREATE TABLE IF NOT EXISTS dhcp.otel_logs
(
    Timestamp DateTime64(9),
    TimestampTime DateTime DEFAULT toDateTime(Timestamp),

    -- Trace context. shadowdhcp does not emit traces, so these are empty.
    TraceId String,
    SpanId String,
    TraceFlags UInt8,

    -- Severity (OTLP spec: TRACE=1, DEBUG=5, INFO=9, WARN=13, ERROR=17)
    SeverityText LowCardinality(String),
    SeverityNumber UInt8,

    -- Service identification
    ServiceName LowCardinality(String),
    Body String,

    -- Resource attributes carry host.name and service.name; log attributes
    -- carry per-event fields like target plus the enclosing span's
    -- #[instrument] fields (mac, xid, client_id, ...).
    ResourceSchemaUrl String,
    ResourceAttributes Map(LowCardinality(String), String),
    ScopeSchemaUrl String,
    ScopeName String,
    ScopeVersion String,
    ScopeAttributes Map(LowCardinality(String), String),
    LogAttributes Map(LowCardinality(String), String),

    INDEX idx_trace_id TraceId TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_res_attr_key mapKeys(ResourceAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_res_attr_value mapValues(ResourceAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_log_attr_key mapKeys(LogAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_log_attr_value mapValues(LogAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_body Body TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 1
)
ENGINE = MergeTree
PARTITION BY toDate(TimestampTime)
ORDER BY (ServiceName, TimestampTime, Timestamp)
TTL TimestampTime + INTERVAL 30 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- Example queries for otel_logs:

-- Recent errors
-- SELECT Timestamp, Body, LogAttributes FROM dhcp.otel_logs WHERE SeverityText = 'ERROR' ORDER BY Timestamp DESC LIMIT 100;

-- Logs by source module (the `target` log attribute is the Rust module path)
-- SELECT Timestamp, Body FROM dhcp.otel_logs WHERE LogAttributes['target'] LIKE 'shadowdhcp::v6%' ORDER BY Timestamp DESC LIMIT 50;

-- Logs for a particular MAC (set as a span field via #[instrument])
-- SELECT Timestamp, Body FROM dhcp.otel_logs WHERE LogAttributes['mac'] = '00-11-22-33-44-55' ORDER BY Timestamp DESC LIMIT 100;

-- Logs from a specific host
-- SELECT Timestamp, SeverityText, Body FROM dhcp.otel_logs WHERE ResourceAttributes['host.name'] = 'dhcp-sea-01' ORDER BY Timestamp DESC LIMIT 100;

-- Severity histogram, last hour
-- SELECT SeverityText, count() FROM dhcp.otel_logs WHERE Timestamp > now() - INTERVAL 1 HOUR GROUP BY SeverityText ORDER BY 2 DESC;
