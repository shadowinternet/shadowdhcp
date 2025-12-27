-- ClickHouse schema for shadow_dhcpv6 analytics
-- Run with: clickhouse-client --password --multiquery < clickhouse_schema.sql

CREATE DATABASE IF NOT EXISTS dhcp;

-- DHCPv4 events table
CREATE TABLE IF NOT EXISTS dhcp.events_v4
(
    -- Timing
    timestamp_ms UInt64,
    timestamp DateTime64(3) MATERIALIZED fromUnixTimestamp64Milli(timestamp_ms),

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
    extractor_used LowCardinality(Nullable(String)),  -- extractor name if option82

    -- Result
    success UInt8,
    failure_reason LowCardinality(Nullable(String)),

    -- Indices
    INDEX idx_host host_name TYPE bloom_filter GRANULARITY 4,
    INDEX idx_mac mac_address TYPE bloom_filter GRANULARITY 4,
    INDEX idx_success success TYPE minmax GRANULARITY 1,
    INDEX idx_reservation_ipv4 reservation_ipv4 TYPE bloom_filter GRANULARITY 4,
    INDEX idx_match_method match_method TYPE bloom_filter GRANULARITY 4
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
    timestamp_ms UInt64,
    timestamp DateTime64(3) MATERIALIZED fromUnixTimestamp64Milli(timestamp_ms),

    -- Server identification
    host_name LowCardinality(String) DEFAULT '',

    -- Message info
    message_type LowCardinality(String),
    xid String,
    relay_addr IPv6,
    relay_link_addr IPv6,
    relay_peer_addr IPv6,

    -- Request data (from client/relay)
    mac_address Nullable(String),
    client_id Nullable(String),
    option1837_interface Nullable(String),
    option1837_remote Nullable(String),
    requested_ipv6_na Nullable(IPv6),
    requested_ipv6_pd Nullable(String),  -- stored as "prefix/len" string

    -- Reservation data (what matched)
    reservation_ipv6_na Nullable(IPv6),
    reservation_ipv6_pd Nullable(String),  -- stored as "prefix/len" string
    reservation_ipv4 Nullable(IPv4),
    reservation_mac Nullable(String),
    reservation_duid Nullable(String),
    reservation_option1837_interface Nullable(String),
    reservation_option1837_remote Nullable(String),

    -- Match info (how was reservation found)
    match_method LowCardinality(Nullable(String)),  -- 'mac', 'duid', 'option1837'
    extractor_used LowCardinality(Nullable(String)),  -- extractor name if option1837

    -- Result
    success UInt8,
    failure_reason LowCardinality(Nullable(String)),

    -- Indices
    INDEX idx_host host_name TYPE bloom_filter GRANULARITY 4,
    INDEX idx_mac mac_address TYPE bloom_filter GRANULARITY 4,
    INDEX idx_client_id client_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_success success TYPE minmax GRANULARITY 1,
    INDEX idx_reservation_ipv6_na reservation_ipv6_na TYPE bloom_filter GRANULARITY 4,
    INDEX idx_match_method match_method TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (host_name, relay_addr, timestamp)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Materialized view for frequent clients (v4)
-- Uses assumeNotNull since we filter WHERE mac_address IS NOT NULL
CREATE MATERIALIZED VIEW IF NOT EXISTS dhcp.frequent_clients_v4_mv
ENGINE = SummingMergeTree()
ORDER BY (host_name, mac_address, date)
AS SELECT
    host_name,
    assumeNotNull(mac_address) AS mac_address,
    toDate(timestamp) AS date,
    count() AS request_count,
    countIf(success = 1) AS success_count,
    countIf(success = 0) AS failure_count
FROM dhcp.events_v4
WHERE mac_address IS NOT NULL
GROUP BY host_name, mac_address, date;

-- Materialized view for frequent clients (v6)
CREATE MATERIALIZED VIEW IF NOT EXISTS dhcp.frequent_clients_v6_mv
ENGINE = SummingMergeTree()
ORDER BY (host_name, mac_address, date)
AS SELECT
    host_name,
    assumeNotNull(mac_address) AS mac_address,
    toDate(timestamp) AS date,
    count() AS request_count,
    countIf(success = 1) AS success_count,
    countIf(success = 0) AS failure_count
FROM dhcp.events_v6
WHERE mac_address IS NOT NULL
GROUP BY host_name, mac_address, date;

-- Materialized view for relay statistics (per host)
CREATE MATERIALIZED VIEW IF NOT EXISTS dhcp.relay_stats_v4_mv
ENGINE = SummingMergeTree()
ORDER BY (host_name, relay_addr, date)
AS SELECT
    host_name,
    relay_addr,
    toDate(timestamp) AS date,
    count() AS request_count,
    countIf(success = 1) AS success_count,
    countIf(success = 0) AS failure_count
FROM dhcp.events_v4
GROUP BY host_name, relay_addr, date;

CREATE MATERIALIZED VIEW IF NOT EXISTS dhcp.relay_stats_v6_mv
ENGINE = SummingMergeTree()
ORDER BY (host_name, relay_addr, date)
AS SELECT
    host_name,
    relay_addr,
    toDate(timestamp) AS date,
    count() AS request_count,
    countIf(success = 1) AS success_count,
    countIf(success = 0) AS failure_count
FROM dhcp.events_v6
GROUP BY host_name, relay_addr, date;

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

-- Events from specific server
-- SELECT * FROM dhcp.events_v4 WHERE host_name = 'dhcp-server-01' ORDER BY timestamp DESC LIMIT 100;

-- Request count per server
-- SELECT host_name, sum(request_count) as total FROM dhcp.relay_stats_v4_mv GROUP BY host_name;

-- =============================================================================
-- OTLP-compatible logs table for HyperDX
-- =============================================================================

-- This schema follows the OpenTelemetry log data model for HyperDX compatibility
-- See: https://opentelemetry.io/docs/specs/otel/logs/data-model/
CREATE TABLE IF NOT EXISTS dhcp.otel_logs
(
    -- Timestamps
    Timestamp Int64,  -- Unix nanoseconds
    TimestampTime DateTime64(9) MATERIALIZED fromUnixTimestamp64Nano(Timestamp),

    -- Severity
    SeverityText LowCardinality(String),  -- TRACE, DEBUG, INFO, WARN, ERROR
    SeverityNumber UInt8,  -- 1-24 per OTLP spec

    -- Log content
    Body String,

    -- Service identification
    ServiceName LowCardinality(String),
    HostName LowCardinality(String) DEFAULT '',

    -- Trace context (for correlation with distributed tracing)
    TraceId String DEFAULT '',
    SpanId String DEFAULT '',
    TraceFlags UInt8 DEFAULT 0,

    -- Attributes as JSON (flexible schema)
    ResourceAttributes String DEFAULT '{}',  -- JSON object
    LogAttributes String DEFAULT '{}',  -- JSON object

    -- Indices
    INDEX idx_severity SeverityNumber TYPE minmax GRANULARITY 1,
    INDEX idx_service ServiceName TYPE bloom_filter GRANULARITY 4,
    INDEX idx_host HostName TYPE bloom_filter GRANULARITY 4,
    INDEX idx_trace_id TraceId TYPE bloom_filter GRANULARITY 4,
    INDEX idx_body Body TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(TimestampTime)
ORDER BY (ServiceName, HostName, TimestampTime)
TTL TimestampTime + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- Materialized view for log level counts per service and host
CREATE MATERIALIZED VIEW IF NOT EXISTS dhcp.log_severity_stats_mv
ENGINE = SummingMergeTree()
ORDER BY (ServiceName, HostName, SeverityText, date)
AS SELECT
    ServiceName,
    HostName,
    SeverityText,
    toDate(TimestampTime) AS date,
    count() AS log_count
FROM dhcp.otel_logs
GROUP BY ServiceName, HostName, SeverityText, date;

-- Example queries for otel_logs:

-- Recent errors
-- SELECT TimestampTime, Body, LogAttributes FROM dhcp.otel_logs WHERE SeverityText = 'ERROR' ORDER BY TimestampTime DESC LIMIT 100;

-- Logs by target module
-- SELECT TimestampTime, Body FROM dhcp.otel_logs WHERE JSONExtractString(LogAttributes, 'target') LIKE 'shadow_dhcpv6::v6%' ORDER BY TimestampTime DESC LIMIT 50;

-- Log volume by severity
-- SELECT SeverityText, sum(log_count) as total FROM dhcp.log_severity_stats_mv GROUP BY SeverityText;

-- Logs from specific host
-- SELECT TimestampTime, SeverityText, Body FROM dhcp.otel_logs WHERE HostName = 'dhcp-server-01' ORDER BY TimestampTime DESC LIMIT 100;

-- Error count by host
-- SELECT HostName, sum(log_count) as errors FROM dhcp.log_severity_stats_mv WHERE SeverityText = 'ERROR' GROUP BY HostName;
