/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fct_T_threat",
    "datasource_mv": "fv_fct_T_threat_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fct_T_threat_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_T_threat_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_T_threat_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_T_threat_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_T_threat_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fct_T_threat_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fct_T_threat_5min_sp$SPID (
    timescale DateTime, dvid Int32, f_user Nullable(String),
    _adomoid UInt64,
    fgtserial LowCardinality(Nullable(String)),
    emsserial LowCardinality(Nullable(String)),
    threat_s LowCardinality(Nullable(String)),
    threatlevel_s Int8,
    srcip Nullable(IPv6),
    dstip Nullable(IPv6),
    incident_block_state AggregateFunction(sum, Int64),
    incident_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, fgtserial, emsserial)
ORDER BY (_adomoid, dvid, timescale,
         fgtserial, emsserial,
         threat_s, threatlevel_s, f_user, srcip, dstip)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fct_T_threat_hour_sp$SPID AS siem.fv_fct_T_threat_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fct_T_threat_day_sp$SPID AS siem.fv_fct_T_threat_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fct_T_threat_5min_mv_sp$SPID
TO siem.fv_fct_T_threat_5min_sp$SPID
AS SELECT _adomoid, dvid, fv_timescale_func(itime, 300, 0) AS timescale,
       fgtserial, emsserial, threat_s, threatlevel_s, f_user, srcip, dstip, 
       sumState(toInt64(incident_block)) AS incident_block_state,
       sumState(toInt64(incidents)) AS incident_state
       FROM (
           SELECT
               itime,
               dvid,
               _adomoid,
               _devlogtype,
               $LOGFIELD-fgtserial,
               $LOGFIELD-emsserial,
               $LOGFIELD-threat-threat_s,
               $LOGFIELD-level,
               (CASE WHEN level IN ('critical', 'alert', 'emergency') THEN '5' WHEN level='error' THEN '4' WHEN level='warning' THEN '3' WHEN level='notice' THEN '2' ELSE '1' END) AS threatlevel_s,
               $LOGFIELD-user-f_user,
               $LOGFIELD-srcip,
               $LOGFIELD-dstip,
               $LOGFIELD-utmaction,
               $LOGFIELD-threat,
               (CASE WHEN utmaction='blocked' THEN 1 ELSE 0 END) AS incident_block,
               1 AS incidents
          FROM siem.ulog_sp$SPID
          WHERE _devlogtype = 3016 AND nullifna(threat) IS NOT NULL
)
GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
         threat_s, threatlevel_s, f_user, srcip, dstip;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fct_T_threat_hour_mv_sp$SPID
TO siem.fv_fct_T_threat_hour_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 3600, 0) AS timescale,
       fgtserial, emsserial, threat_s, threatlevel_s, f_user, srcip, dstip,
       sumState(incident_block) AS incident_block_state,
       sumState(incidents) AS incident_state
FROM (
   SELECT _adomoid, dvid,
       timescale,
       fgtserial, emsserial, threat_s, threatlevel_s, f_user, srcip, dstip,
       sumMerge(incident_block_state) AS incident_block,
       sumMerge(incident_state) AS incidents
    FROM siem.fv_fct_T_threat_5min_sp$SPID
    GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
             threat_s, threatlevel_s, f_user, srcip, dstip
)
GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
         threat_s, threatlevel_s, f_user, srcip, dstip;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fct_T_threat_day_mv_sp$SPID
TO siem.fv_fct_T_threat_day_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 28800, 0) AS timescale,
       fgtserial, emsserial, threat_s, threatlevel_s, f_user, srcip, dstip,
       sumState(incident_block) AS incident_block_state,
       sumState(incidents) AS incident_state
FROM (
   SELECT _adomoid, dvid,
       timescale,
       fgtserial, emsserial, threat_s, threatlevel_s, f_user, srcip, dstip,
       sumMerge(incident_block_state) AS incident_block,
       sumMerge(incident_state) AS incidents
    FROM siem.fv_fct_T_threat_hour_sp$SPID
    GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
             threat_s, threatlevel_s, f_user, srcip, dstip
)
GROUP BY _adomoid, timescale, dvid, fgtserial, emsserial,
         threat_s, threatlevel_s, f_user, srcip, dstip;


ALTER TABLE siem.fv_fct_T_threat_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
