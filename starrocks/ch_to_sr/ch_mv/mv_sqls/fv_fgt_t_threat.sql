/*
{
    "type": "sp_mv",
    "version": "070600.3454",
    "name": "fv_fgt_t_threat",
    "datasource_mv": "fv_fgt_t_threat_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_t_threat_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_threat_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_threat_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_threat_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_threat_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_threat_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_threat_5min_sp$SPID (
    timescale DateTime, dvid Int32, f_user Nullable(String), f_group Nullable(String),
    _adomoid UInt64,
    dstowner LowCardinality(Nullable(String)),
    dstintf LowCardinality(Nullable(String)),
    dstip Nullable(IPv6),
    dstuuid Nullable(UUID),
    srcintfrole LowCardinality(Nullable(String)),
    dstintfrole LowCardinality(Nullable(String)),
    epid Int32,
    srcmac Nullable(String),
    srcip Nullable(IPv6),
    srcintf LowCardinality(Nullable(String)),
    srcuuid Nullable(UUID) CODEC(LZ4),
    app_group Nullable(String),
    d_flags UInt32,
    domain Nullable(String),
    catdesc LowCardinality(Nullable(String)),
    policymode LowCardinality(Nullable(String)),
    policyid Nullable(UInt32),
    policytype LowCardinality(Nullable(String)),
    poluuid Nullable(UUID),
    threat_s Nullable(String),
    threattype_s Nullable(String),
    threatlevel_s Int8,
    dstcountry Nullable(String),
    devtype Nullable(String),
    threatlevel_state AggregateFunction(max, Int8),
    threatweight_state AggregateFunction(sum, Int64),
    thwgt_cri_state AggregateFunction(sum, Int64),
    thwgt_hig_state AggregateFunction(sum, Int64),
    thwgt_med_state AggregateFunction(sum, Int64),
    thwgt_low_state AggregateFunction(sum, Int64),
    incident_block_state AggregateFunction(sum, Int64),
    incident_state AggregateFunction(sum, Int64),
    threatblock_state AggregateFunction(sum, Int64),
    sessions_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, srcintfrole, dstintfrole)
ORDER BY (_adomoid, dvid, timescale, srcintfrole, dstintfrole,
         app_group, d_flags, domain, catdesc, f_user, srcip, srcuuid, srcintf, srcmac,
         dstcountry, devtype, dstip, dstuuid, dstintf, dstowner, policyid, policytype)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_threat_hour_sp$SPID AS siem.fv_fgt_t_threat_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_threat_day_sp$SPID AS siem.fv_fgt_t_threat_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_threat_5min_mv_sp$SPID
TO siem.fv_fgt_t_threat_5min_sp$SPID
AS SELECT _adomoid, dvid, srcintfrole, dstintfrole,
       fv_timescale_func(itime, 300, 0) AS timescale,
       srcip, srcintf, srcuuid, srcmac,
       dstip, dstintf, dstuuid, dstowner,
       app_group,
       d_flags,
       domain,
       catdesc,
       policymode,
       policyid,
       policytype,
       poluuid,
       f_user,
       threat_s,
       threattype_s,
       threatlevel_s,
       dstcountry,
       devtype,
       sumState(toInt64(threatwgt)) AS threatweight_state,
       sumState(thwgt_cri) AS thwgt_cri_state,
       sumState(thwgt_hig) AS thwgt_hig_state,
       sumState(thwgt_med) AS thwgt_med_state,
       sumState(thwgt_low) AS thwgt_low_state,
       sumState(toInt64(incident_block*threatcnt)) AS incident_block_state,
       sumState(toInt64(threatcnt)) AS incident_state,
       sumState(threat_block) AS threatblock_state
    FROM ( 
      SELECT *,
           `unnested.1` AS threat_s,
           `unnested.2` AS threattype_s,
           `unnested.3` AS threatlevel_s,
           `unnested.4` AS threatwgt,
           `unnested.5` AS threatcnt,
           (CASE WHEN threatlevel_s=4 THEN (threatwgt*threatcnt) ELSE 0 END) AS thwgt_cri,
           (CASE WHEN threatlevel_s=3 THEN (threatwgt*threatcnt) ELSE 0 END) AS thwgt_hig,
           (CASE WHEN threatlevel_s=2 THEN (threatwgt*threatcnt) ELSE 0 END) AS thwgt_med,
           (CASE WHEN threatlevel_s=1 THEN (threatwgt*threatcnt) ELSE 0 END) AS thwgt_low,
           (CASE WHEN incident_block=1 THEN threatwgt*threatcnt ELSE 0 END) AS threat_block
       FROM (
           SELECT
               itime,
               dvid,
               _adomoid,
               _devlogtype,
               $LOGFIELD-srcintfrole,
               $LOGFIELD-dstintfrole,
               $LOGFIELD-user,
               $LOGFIELD-unauthuser,
               $LOGFIELD-srcip,
               $LOGFIELD-srcintf,
               $LOGFIELD-srcuuid,
               $LOGFIELD-srcmac,
               $LOGFIELD-srcname,
               $LOGFIELD-dstip,
               $LOGFIELD-dstintf,
               $LOGFIELD-dstuuid,
               $LOGFIELD-dstowner,
               $LOGFIELD-dstmac,
               $LOGFIELD-srcswversion,
               $LOGFIELD-app,
               $LOGFIELD-policymode,
               $LOGFIELD-policyid,
               $LOGFIELD-policytype,
               $LOGFIELD-poluuid,
               app_group_name(app) AS app_group, logflag, 
               $LOGFIELD-hostname,
               (CASE WHEN(bitAnd(logflag, 64) > 0) THEN hostname ELSE root_domain(hostname) END) AS domain,
               $LOGFIELD-catdesc,
               $LOGFIELD-unauthuser,
               $LOGFIELD-threats,
               $LOGFIELD-appcat,
               $LOGFIELD-threattyps-threattypes,
               coalesce(nullifna(user), nullifna(unauthuser)) AS f_user,
               $LOGFIELD-dstcountry,
               $LOGFIELD-devtype,
               $LOGFIELD-threatlvls-threatlevels,
               $LOGFIELD-threatwgts,
               $LOGFIELD-threatcnts,
               (CASE WHEN appcat='unscanned' THEN 1 ELSE 0 END) AS d_flags,
               untuple(arrayJoin(arrayZip(threats, threattypes, threatlevels, threatwgts, threatcnts))) AS unnested,
               (CASE WHEN (bitAnd(logflag,2)>0) THEN 1 ELSE 0 END) AS incident_block
          FROM siem.tlog_sp$SPID
          WHERE _devlogtype = 10 AND threats IS NOT NULL)
)
GROUP BY _adomoid, dvid, srcintfrole, dstintfrole, timescale,
     threat_s, threattype_s, threatlevel_s,
     app_group, d_flags, domain, catdesc, f_user, srcip, srcuuid, srcintf, srcmac,
     dstcountry, devtype, dstip, dstuuid, dstintf, dstowner, policymode, policyid, policytype, poluuid;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_threat_hour_mv_sp$SPID
TO siem.fv_fgt_t_threat_hour_sp$SPID
AS SELECT _adomoid, dvid, srcintfrole, dstintfrole,
       fv_timescale_func(timescale, 3600, 0) AS timescale,
       f_user,
       srcip, srcintf, srcuuid, srcmac,
       dstip, dstintf, dstuuid, dstowner,
       app_group,
       d_flags,
       domain,
       catdesc,
       policymode,
       policyid,
       policytype,
       poluuid,
       threat_s, threattype_s, threatlevel_s,
       dstcountry,
       devtype,
       sumState(threatwgt) AS threatweight_state,
       sumState(thwgt_cri) AS thwgt_cri_state,
       sumState(thwgt_hig) AS thwgt_hig_state,
       sumState(thwgt_med) AS thwgt_med_state,
       sumState(thwgt_low) AS thwgt_low_state,
       sumState(incident_block) AS incident_block_state,
       sumState(threat_block) AS threatblock_state,
       sumState(incident) AS incident_state
FROM (
   SELECT _adomoid, dvid, srcintfrole, dstintfrole,
       timescale, f_user,
       srcip, srcintf, srcuuid, srcmac,
       dstip, dstintf, dstuuid, dstowner,
       app_group,
       d_flags,
       domain,
       catdesc,
       policymode,
       policyid,
       policytype,
       poluuid,
       threat_block,
       threat_s, threattype_s, threatlevel_s,
       sumMerge(threatweight_state) AS threatwgt,
       dstcountry,
       devtype,
       sumMerge(threatblock_state) AS threat_block,
       sumMerge(thwgt_cri_state) AS thwgt_cri,
       sumMerge(thwgt_hig_state) AS thwgt_hig,
       sumMerge(thwgt_med_state) AS thwgt_med,
       sumMerge(thwgt_low_state) AS thwgt_low,
       sumMerge(incident_block_state) AS incident_block,
       sumMerge(incident_state) AS incident
    FROM siem.fv_fgt_t_threat_5min_sp$SPID
    GROUP BY _adomoid, dvid, srcintfrole, dstintfrole, timescale,
         threat_s, threattype_s, threatlevel_s,
         app_group, d_flags, domain, catdesc, f_user, srcip, srcuuid, srcintf, srcmac,
         dstcountry, devtype, dstip, dstuuid, dstintf, dstowner,
         policymode, policyid, policytype, poluuid
)
GROUP BY _adomoid, dvid, srcintfrole, dstintfrole, timescale,
     threat_s, threattype_s, threatlevel_s,
     app_group, d_flags, domain, catdesc, f_user, srcip, srcuuid, srcintf, srcmac,
     dstcountry, devtype, dstip, dstuuid, dstintf, dstowner,
     policymode, policyid, policytype, poluuid;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_threat_day_mv_sp$SPID
TO siem.fv_fgt_t_threat_day_sp$SPID
AS SELECT _adomoid, dvid, srcintfrole, dstintfrole,
       fv_timescale_func(timescale, 28800, 0) AS timescale,
       f_user,
       srcip, srcintf, srcuuid, srcmac,
       dstip, dstintf, dstuuid, dstowner,
       app_group,
       d_flags,
       domain,
       catdesc,
       policymode,
       policyid,
       policytype,
       poluuid,
       threat_s, threattype_s, threatlevel_s,
       dstcountry,
       devtype,
       sumState(threatwgt) AS threatweight_state,
       sumState(thwgt_cri) AS thwgt_cri_state,
       sumState(thwgt_hig) AS thwgt_hig_state,
       sumState(thwgt_med) AS thwgt_med_state,
       sumState(thwgt_low) AS thwgt_low_state,
       sumState(incident_block) AS incident_block_state,
       sumState(threat_block) AS threatblock_state,
       sumState(incident) AS incident_state
FROM (
   SELECT _adomoid, dvid, srcintfrole, dstintfrole,
       timescale, f_user,
       srcip, srcintf, srcuuid, srcmac,
       dstip, dstintf, dstuuid, dstowner,
       app_group,
       d_flags,
       domain,
       catdesc,
       policymode,
       policyid,
       policytype,
       poluuid,
       threat_block,
       threat_s, threattype_s, threatlevel_s,
       sumMerge(threatweight_state) AS threatwgt,
       dstcountry,
       devtype,
       sumMerge(threatblock_state) AS threat_block,
       sumMerge(thwgt_cri_state) AS thwgt_cri,
       sumMerge(thwgt_hig_state) AS thwgt_hig,
       sumMerge(thwgt_med_state) AS thwgt_med,
       sumMerge(thwgt_low_state) AS thwgt_low,
       sumMerge(incident_block_state) AS incident_block,
       sumMerge(incident_state) AS incident
    FROM siem.fv_fgt_t_threat_hour_sp$SPID
    GROUP BY _adomoid, dvid, srcintfrole, dstintfrole, timescale,
         threat_s, threattype_s, threatlevel_s,
         app_group, d_flags, domain, catdesc, f_user, srcip, srcuuid, srcintf, srcmac,
         dstcountry, devtype, dstip, dstuuid, dstintf, dstowner,
         policymode, policyid, policytype, poluuid
)
GROUP BY _adomoid, dvid, srcintfrole, dstintfrole, timescale,
     threat_s, threattype_s, threatlevel_s,
     app_group, d_flags, domain, catdesc, f_user, srcip, srcuuid, srcintf, srcmac,
     dstcountry, devtype, dstip, dstuuid, dstintf, dstowner,
     policymode, policyid, policytype, poluuid;

ALTER TABLE siem.fv_fgt_t_threat_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
