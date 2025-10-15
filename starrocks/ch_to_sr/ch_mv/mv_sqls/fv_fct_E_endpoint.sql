/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fct_E_endpoint",
    "datasource_mv": "fv_fct_E_endpoint_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fct_E_endpoint_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_E_endpoint_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_E_endpoint_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_E_endpoint_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_E_endpoint_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_E_endpoint_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fct_E_endpoint_5min_sp$SPID (
    timescale DateTime, dvid Int32, f_user Nullable(String),
    _adomoid UInt64,
    fgtserial LowCardinality(Nullable(String)),
    emsserial LowCardinality(Nullable(String)),
    uid  Nullable(UUID),
    hostname Nullable(String),
    subtype Nullable(String),
    os Nullable(String),
    fctver Nullable(String),
    virus LowCardinality(Nullable(String)),
    srcip_state AggregateFunction(max, Nullable(IPv6)),
    events_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, fgtserial, emsserial)
ORDER BY (_adomoid, dvid, timescale,
         fgtserial, emsserial, uid, f_user, hostname)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fct_E_endpoint_hour_sp$SPID AS siem.fv_fct_E_endpoint_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fct_E_endpoint_day_sp$SPID AS siem.fv_fct_E_endpoint_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fct_E_endpoint_5min_mv_sp$SPID
TO siem.fv_fct_E_endpoint_5min_sp$SPID
AS SELECT _adomoid, dvid, fv_timescale_func(itime, 300, 0) AS timescale,
       fgtserial, emsserial,
       uid, f_user, hostname, subtype, os, fctver, virus,
       maxState(deviceip) AS srcip_state,
       sumState(toInt64(events)) AS events_state
       FROM (
           SELECT
               itime,
               dvid,
               _adomoid,
               _devlogtype,
               $LOGFIELD-fgtserial,
               $LOGFIELD-emsserial,
               $LOGFIELD-uid,
               $LOGFIELD-user-f_user,
               $LOGFIELD-hostname,
               subtype,
               $LOGFIELD-os,
               $LOGFIELD-fctver,
               $LOGFIELD-virus,
               $LOGFIELD-deviceip,
               1 AS events
          FROM siem.elog_sp$SPID
          WHERE _devlogtype = 3015 AND subtype != 'admin' AND  (logflag IS NULL OR bitAnd(logflag,8)=0)
)
GROUP BY _adomoid, dvid, timescale, fgtserial, emsserial,
         uid, f_user, hostname, subtype, os, fctver, virus;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fct_E_endpoint_hour_mv_sp$SPID
TO siem.fv_fct_E_endpoint_hour_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 3600, 0) AS timescale,
       fgtserial, emsserial, uid, f_user, hostname, subtype, os, fctver, virus,
       maxState(srcip) AS srcip_state,
       sumState(events) AS events_state
FROM (
   SELECT _adomoid, dvid,
       timescale,
       fgtserial, emsserial, uid, f_user, hostname, subtype, os, fctver, virus,
       maxMerge(srcip_state) AS srcip,
       sumMerge(events_state) AS events
    FROM siem.fv_fct_E_endpoint_5min_sp$SPID
    GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
             uid, f_user, hostname, subtype, os, fctver, virus
)
GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
         uid, f_user, hostname, subtype, os, fctver, virus;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fct_E_endpoint_day_mv_sp$SPID
TO siem.fv_fct_E_endpoint_day_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 28800, 0) AS timescale,
       fgtserial, emsserial, uid, f_user, hostname, subtype, os, fctver, virus,
       maxState(srcip) AS srcip_state,
       sumState(events) AS events_state
FROM (
   SELECT _adomoid, dvid,
       timescale,
       fgtserial, emsserial, uid, f_user, hostname, subtype, os, fctver, virus,
       maxMerge(srcip_state) AS srcip,
       sumMerge(events_state) AS events
    FROM siem.fv_fct_E_endpoint_hour_sp$SPID
    GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
             uid, f_user, hostname, subtype, os, fctver, virus
)
GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
         uid, f_user, hostname, subtype, os, fctver, virus;

ALTER TABLE siem.fv_fct_E_endpoint_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
