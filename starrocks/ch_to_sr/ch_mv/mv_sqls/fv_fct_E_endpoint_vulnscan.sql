/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fct_E_endpoint_vulnscan",
    "datasource_mv": "fv_fct_E_endpoint_vulnscan_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fct_E_endpoint_vulnscan_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_E_endpoint_vulnscan_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_E_endpoint_vulnscan_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_E_endpoint_vulnscan_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_E_endpoint_vulnscan_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_E_endpoint_vulnscan_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fct_E_endpoint_vulnscan_5min_sp$SPID (
    timescale DateTime, dvid Int32, f_user Nullable(String),
    _adomoid UInt64,
    fgtserial LowCardinality(Nullable(String)),
    emsserial LowCardinality(Nullable(String)),
    virus LowCardinality(Nullable(String)),
    file Nullable(String),
    action LowCardinality(Nullable(String)),
    hostname LowCardinality(Nullable(String)),
    events_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, fgtserial, emsserial, virus, file, action, hostname)
ORDER BY (_adomoid, dvid, timescale,
         fgtserial, emsserial, virus, file, action, hostname)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fct_E_endpoint_vulnscan_hour_sp$SPID AS siem.fv_fct_E_endpoint_vulnscan_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fct_E_endpoint_vulnscan_day_sp$SPID AS siem.fv_fct_E_endpoint_vulnscan_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fct_E_endpoint_vulnscan_5min_mv_sp$SPID
TO siem.fv_fct_E_endpoint_vulnscan_5min_sp$SPID
AS SELECT _adomoid, dvid, fv_timescale_func(itime, 300, 0) AS timescale,
       fgtserial, emsserial,
       virus,
       file,
       action,
       hostname,
       sumState(toInt64(events)) AS events_state
       FROM (
           SELECT
               itime,
               dvid,
               _adomoid,
               _devlogtype,
               $LOGFIELD-fgtserial,
               $LOGFIELD-emsserial,
               $LOGFIELD-virus,
               $LOGFIELD-file,
               $LOGFIELD-action,
               $LOGFIELD-hostname,
               $LOGFIELD-vulnid,
               1 AS events
          FROM siem.elog_sp$SPID
          WHERE _devlogtype = 3015 AND logid_to_int(logid)=45071 AND vulnid > 0
)
GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
         virus, file, action, hostname;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fct_E_endpoint_vulnscan_hour_mv_sp$SPID
TO siem.fv_fct_E_endpoint_vulnscan_hour_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 3600, 0) AS timescale,
       fgtserial, emsserial,
       virus,
       file,
       action,
       hostname,
       sumState(events) AS events_state
FROM (
   SELECT _adomoid, dvid,
       timescale,
       fgtserial, emsserial,
       virus,
       file,
       action,
       hostname,
       sumMerge(events_state) AS events
    FROM siem.fv_fct_E_endpoint_vulnscan_5min_sp$SPID
    GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
             virus, file, action, hostname
)
GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
         virus, file, action, hostname;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fct_E_endpoint_vulnscan_hour_mv_sp$SPID
TO siem.fv_fct_E_endpoint_vulnscan_hour_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 3600, 0) AS timescale,
       fgtserial, emsserial,
       virus,
       file,
       action,
       hostname,
       sumState(events) AS events_state
FROM (
   SELECT _adomoid, dvid,
       timescale,
       fgtserial, emsserial,
       virus,
       file,
       action,
       hostname,
       sumMerge(events_state) AS events
    FROM siem.fv_fct_E_endpoint_vulnscan_5min_sp$SPID
    GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
             virus, file, action, hostname
)
GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
         virus, file, action, hostname;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fct_E_endpoint_vulnscan_day_mv_sp$SPID
TO siem.fv_fct_E_endpoint_vulnscan_day_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 28800, 0) AS timescale,
       fgtserial, emsserial,
       virus,
       file,
       action,
       hostname,
       sumState(events) AS events_state
FROM (
   SELECT _adomoid, dvid,
       timescale,
       fgtserial, emsserial,
       virus,
       file,
       action,
       hostname,
       sumMerge(events_state) AS events
    FROM siem.fv_fct_E_endpoint_vulnscan_hour_sp$SPID
    GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
             virus, file, action, hostname
)
GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
         virus, file, action, hostname;

ALTER TABLE siem.fv_fct_E_endpoint_vulnscan_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
