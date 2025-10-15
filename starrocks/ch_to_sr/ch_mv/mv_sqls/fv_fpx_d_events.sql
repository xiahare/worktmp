/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fpx_d_events",
    "datasource_mv": "fv_fpx_d_events_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fpx_d_events_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fpx_d_events_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fpx_d_events_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fpx_d_events_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fpx_d_events_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fpx_d_events_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fpx_d_events_5min_sp$SPID (
    dvid Int32,
     _adomoid UInt64,
    timescale DateTime,
    severity LowCardinality(Nullable(String)),
    hostname LowCardinality(Nullable(String)),
    srcip Nullable(IPv6),
    service LowCardinality(Nullable(String)),
    incident_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, severity, hostname)
ORDER BY (_adomoid, dvid, timescale, severity, hostname)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fpx_d_events_hour_sp$SPID AS siem.fv_fpx_d_events_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fpx_d_events_day_sp$SPID AS siem.fv_fpx_d_events_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fpx_d_events_5min_mv_sp$SPID
TO siem.fv_fpx_d_events_5min_sp$SPID
AS SELECT
    dvid, _adomoid,
    fv_timescale_func(itime, 300, 0) AS timescale,
    severity, hostname, srcip, service,
    sumState(toInt64(incident)) AS incident_state
    FROM (
       SELECT dvid, _adomoid, itime,
           $LOGFIELD-severity,
           $LOGFIELD-hostname,
           $LOGFIELD-srcip,
           $LOGFIELD-service,
           $LOGFIELD-action,
           1 AS incident
      FROM siem.ulog_sp$SPID
      WHERE _devlogtype = 15003 AND hostname IS NOT NULL AND action IN ('pass', 'block')
)
GROUP BY _adomoid, dvid, timescale, severity, hostname, srcip, service;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fpx_d_events_hour_mv_sp$SPID
TO siem.fv_fpx_d_events_hour_sp$SPID
AS SELECT
    dvid, _adomoid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    severity, hostname, srcip, service,
    sumState(incidents) AS incident_state
    FROM (
        SELECT
        dvid, _adomoid,
        timescale,
        severity, hostname, srcip, service,
        sumMerge(incident_state) AS incidents
      FROM siem.fv_fpx_d_events_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale, severity, hostname, srcip, service
)
GROUP BY _adomoid, dvid, timescale, severity, hostname, srcip, service;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fpx_d_events_day_mv_sp$SPID
TO siem.fv_fpx_d_events_day_sp$SPID
AS SELECT
    dvid, _adomoid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    severity, hostname, srcip, service,
    sumState(incidents) AS incident_state
    FROM (
        SELECT
        dvid, _adomoid,
        timescale,
        severity, hostname, srcip, service,
        sumMerge(incident_state) AS incidents
      FROM siem.fv_fpx_d_events_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale, severity, hostname, srcip, service
)
GROUP BY _adomoid, dvid, timescale, severity, hostname, srcip, service;

ALTER TABLE siem.fv_fpx_d_events_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
