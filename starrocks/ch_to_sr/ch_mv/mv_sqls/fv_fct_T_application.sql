/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fct_T_application",
    "datasource_mv": "fv_fct_T_application_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fct_T_application_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_T_application_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_T_application_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_T_application_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_T_application_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_T_application_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fct_T_application_5min_sp$SPID (
    timescale DateTime, dvid Int32, f_user Nullable(String),
    _adomoid UInt64,
    fgtserial LowCardinality(Nullable(String)),
    emsserial LowCardinality(Nullable(String)),
    app Nullable(String),
    d_risk Int8,
    bandwidth_state AggregateFunction(sum, Nullable(Int64)),
    traffic_in_state AggregateFunction(sum, Nullable(Int64)),
    traffic_out_state AggregateFunction(sum, Nullable(Int64)),
    session_block_state AggregateFunction(sum, Int64),
    sessions_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, fgtserial, emsserial)
ORDER BY (_adomoid, dvid, timescale,
         fgtserial, emsserial, app, d_risk, f_user)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fct_T_application_hour_sp$SPID AS siem.fv_fct_T_application_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fct_T_application_day_sp$SPID AS siem.fv_fct_T_application_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fct_T_application_5min_mv_sp$SPID
TO siem.fv_fct_T_application_5min_sp$SPID
AS SELECT _adomoid, dvid, fv_timescale_func(itime, 300, 0) AS timescale,
       fgtserial, emsserial, app, d_risk, f_user,
       sumState(toInt64(bandwidth)) AS bandwidth_state,
       sumState(toInt64(traffic_in)) AS traffic_in_state,
       sumState(toInt64(traffic_out)) AS traffic_out_state,
       sumState(toInt64(session_block)) AS session_block_state,
       sumState(toInt64(sessions)) AS sessions_state
       FROM (
           SELECT
               itime,
               dvid,
               _adomoid,
               _devlogtype,
               $LOGFIELD-fgtserial,
               $LOGFIELD-emsserial,
               $LOGFIELD-level,
               $LOGFIELD-user-f_user,
               $LOGFIELD-utmevent,
               $LOGFIELD-remotename,
               $LOGFIELD-utmaction,
               $LOGFIELD-sentbyte,
               $LOGFIELD-rcvdbyte,
               $LOGFIELD-threat,
               threat AS app,
               sentbyte + rcvdbyte AS bandwidth,
               rcvdbyte AS traffic_in,
               sentbyte AS traffic_out,
               (CASE WHEN level IN ('critical', 'alert', 'emergency') THEN '5' WHEN level = 'error' THEN '4' WHEN level = 'warning' THEN '3' WHEN level = 'notice' THEN '2' ELSE '1' END) AS d_risk,
               0 AS session_block,
               1 AS sessions
          FROM siem.ulog_sp$SPID
          WHERE _devlogtype = 3016 AND utmevent = 'appfirewall' AND threat IS NOT NULL
)
GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
         app, d_risk, f_user;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fct_T_application_hour_mv_sp$SPID
TO siem.fv_fct_T_application_hour_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 3600, 0) AS timescale,
       fgtserial, emsserial, app, d_risk, f_user,
       sumState(bandwidth) AS bandwidth_state,
       sumState(traffic_in) AS traffic_in_state,
       sumState(traffic_out) AS traffic_out_state,
       sumState(session_block) AS session_block_state,
       sumState(sessions) AS sessions_state
FROM (
   SELECT _adomoid, dvid, timescale,
       fgtserial, emsserial, app, d_risk, f_user,
       sumMerge(bandwidth_state) AS bandwidth,
       sumMerge(traffic_in_state) AS traffic_in,
       sumMerge(traffic_out_state) AS traffic_out,
       sumMerge(session_block_state) AS session_block,
       sumMerge(sessions_state) AS sessions
    FROM siem.fv_fct_T_application_5min_sp$SPID
    GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
             app, d_risk, f_user
)
GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
        app, d_risk, f_user;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fct_T_application_day_mv_sp$SPID
TO siem.fv_fct_T_application_day_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 28800, 0) AS timescale,
       fgtserial, emsserial, app, d_risk, f_user,
       sumState(bandwidth) AS bandwidth_state,
       sumState(traffic_in) AS traffic_in_state,
       sumState(traffic_out) AS traffic_out_state,
       sumState(session_block) AS session_block_state,
       sumState(sessions) AS sessions_state
FROM (
   SELECT _adomoid, dvid, timescale,
       fgtserial, emsserial, app, d_risk, f_user,
       sumMerge(bandwidth_state) AS bandwidth,
       sumMerge(traffic_in_state) AS traffic_in,
       sumMerge(traffic_out_state) AS traffic_out,
       sumMerge(session_block_state) AS session_block,
       sumMerge(sessions_state) AS sessions
    FROM siem.fv_fct_T_application_hour_sp$SPID
    GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
             app, d_risk, f_user
)
GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
        app, d_risk, f_user;

ALTER TABLE siem.fv_fct_T_application_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
