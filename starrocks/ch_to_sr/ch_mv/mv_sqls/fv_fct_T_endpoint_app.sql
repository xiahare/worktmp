/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fct_T_endpoint_app",
    "datasource_mv": "fv_fct_T_endpoint_app_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fct_T_endpoint_app_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_T_endpoint_app_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_T_endpoint_app_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_T_endpoint_app_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_T_endpoint_app_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_T_endpoint_app_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fct_T_endpoint_app_5min_sp$SPID (
    timescale DateTime, dvid Int32, f_user Nullable(String),
    _adomoid UInt64,
    fgtserial LowCardinality(Nullable(String)),
    emsserial LowCardinality(Nullable(String)),
    hostname Nullable(String),
    srcname Nullable(String),
    srcproduct Nullable(String),
    remotename Nullable(String),
    threat LowCardinality(Nullable(String)),
    fctver Nullable(String),
    subtype LowCardinality(String),
    dstip Nullable(IPv6),
    utmaction Nullable(String),
    srcip_state AggregateFunction(max, Nullable(IPv6)),
    session_block_state AggregateFunction(sum, Int64),
    sessions_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, fgtserial, emsserial, f_user, utmaction, srcname, srcproduct)
ORDER BY (_adomoid, dvid, timescale,
         fgtserial, emsserial,
         f_user, utmaction, srcname, srcproduct,
         hostname, dstip, remotename, threat, fctver, subtype) 
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fct_T_endpoint_app_hour_sp$SPID AS siem.fv_fct_T_endpoint_app_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fct_T_endpoint_app_day_sp$SPID AS siem.fv_fct_T_endpoint_app_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fct_T_endpoint_app_5min_mv_sp$SPID
TO siem.fv_fct_T_endpoint_app_5min_sp$SPID
AS SELECT _adomoid, dvid, fv_timescale_func(itime, 300, 0) AS timescale,
       fgtserial, emsserial,
       hostname,
       f_user,
       srcname,
       srcproduct,
       remotename,
       threat,
       fctver, subtype,
       dstip,
       utmaction,
       maxState(deviceip) AS srcip_state,
       sumState(toInt64(session_block)) as session_block_state,
       sumState(toInt64(sessions)) AS sessions_state
       FROM (
           SELECT
               itime,
               dvid,
               _adomoid,
               _devlogtype,
               $LOGFIELD-fgtserial,
               $LOGFIELD-emsserial,
               $LOGFIELD-hostname,
               $LOGFIELD-user,
               `user` AS f_user,
               $LOGFIELD-srcname,
               $LOGFIELD-srcproduct,
               $LOGFIELD-remotename,
               $LOGFIELD-threat,
               $LOGFIELD-fctver,
               subtype,
               $LOGFIELD-dstip,
               $LOGFIELD-utmaction,
               $LOGFIELD-deviceip,
               (CASE WHEN utmaction NOT IN ('allowed', 'monitored', 'passthrough', 'passthough') THEN 1 ELSE 0 END) AS session_block,
               1 AS sessions
          FROM siem.ulog_sp$SPID
          WHERE _devlogtype = 3016 AND subtype != 'admin'
)
GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
         f_user, utmaction, srcname, srcproduct,
         hostname, dstip, remotename, threat, fctver, subtype;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fct_T_endpoint_app_hour_mv_sp$SPID
TO siem.fv_fct_T_endpoint_app_hour_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 3600, 0) AS timescale,
       fgtserial, emsserial,
       hostname,
       f_user,
       srcname,
       srcproduct,
       remotename,
       threat,
       fctver, subtype,
       dstip,
       utmaction,
       maxState(srcip) as srcip_state,
       sumState(session_block) as session_block_state,
       sumState(sessions) AS sessions_state
FROM (
   SELECT _adomoid, dvid,
       timescale,
       fgtserial, emsserial,
       hostname,
       f_user,
       srcname,
       srcproduct,
       remotename,
       threat,
       fctver, subtype,
       dstip,
       utmaction,
       maxMerge(srcip_state) as srcip,
       sumMerge(session_block_state) as session_block,
       sumMerge(sessions_state) AS sessions
    FROM siem.fv_fct_T_endpoint_app_5min_sp$SPID
    GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
             f_user, utmaction, srcname, srcproduct,
             hostname, dstip, remotename, threat, fctver, subtype
)
GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
         f_user, utmaction, srcname, srcproduct,
         hostname, dstip, remotename, threat, fctver, subtype;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fct_T_endpoint_app_day_mv_sp$SPID
TO siem.fv_fct_T_endpoint_app_day_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 28800, 0) AS timescale,
       fgtserial, emsserial,
       hostname,
       f_user,
       srcname,
       srcproduct,
       remotename,
       threat,
       fctver, subtype,
       dstip,
       utmaction,
       maxState(srcip) as srcip_state,
       sumState(session_block) as session_block_state,
       sumState(sessions) AS sessions_state
FROM (
   SELECT _adomoid, dvid,
       timescale,
       fgtserial, emsserial,
       hostname,
       f_user,
       srcname,
       srcproduct,
       remotename,
       threat,
       fctver, subtype,
       dstip,
       utmaction,
       maxMerge(srcip_state) as srcip,
       sumMerge(session_block_state) as session_block,
       sumMerge(sessions_state) AS sessions
    FROM siem.fv_fct_T_endpoint_app_hour_sp$SPID
    GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
             f_user, utmaction, srcname, srcproduct,
             hostname, dstip, remotename, threat, fctver, subtype
)
GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
         f_user, utmaction, srcname, srcproduct,
         hostname, dstip, remotename, threat, fctver, subtype;

ALTER TABLE siem.fv_fct_T_endpoint_app_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
