/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_a_src_dst_threat",
    "datasource_mv": "fv_fgt_a_src_dst_threat_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_a_src_dst_threat_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_src_dst_threat_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_src_dst_threat_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_src_dst_threat_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_src_dst_threat_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_src_dst_threat_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_a_src_dst_threat_5min_sp$SPID (
    timescale DateTime,
    _adomoid UInt64,
    dvid Int32,
    f_user Nullable(String),
    srcip Nullable(IPv6),
    srcintf LowCardinality(Nullable(String)),
    srcintfrole LowCardinality(Nullable(String)),
    dstip Nullable(IPv6),
    dstintf LowCardinality(Nullable(String)),
    dstintfrole LowCardinality(Nullable(String)),
    dstcountry Nullable(String),
    policyid Nullable(UInt32),
    policytype LowCardinality(Nullable(String)),
    avatar_state  AggregateFunction(max, Nullable(String)),
    epeuid_state  AggregateFunction(max, Nullable(String)),
    threat_state AggregateFunction(groupArray, Nullable(String)),
    threattype_state AggregateFunction(groupArray, LowCardinality(Nullable(String))),
    threatlevel_state AggregateFunction(groupArray, Nullable(Int8)),
    threatweight_state AggregateFunction(sum, Nullable(Int64)),
    threatblock_state AggregateFunction(sum, Nullable(Int64)),
    incident_block_state AggregateFunction(sum, Int64),
    incident_state AggregateFunction(sum, Int64),
    thwgt_cri_state AggregateFunction(sum, Nullable(Int64)),
    thwgt_hig_state AggregateFunction(sum, Nullable(Int64)),
    thwgt_med_state AggregateFunction(sum, Nullable(Int64)),
    thwgt_low_state AggregateFunction(sum, Nullable(Int64))
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole)
ORDER BY (_adomoid, dvid, timescale, 
          f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_a_src_dst_threat_hour_sp$SPID AS siem.fv_fgt_a_src_dst_threat_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_a_src_dst_threat_day_sp$SPID AS siem.fv_fgt_a_src_dst_threat_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_a_src_dst_threat_5min_mv_sp$SPID
TO siem.fv_fgt_a_src_dst_threat_5min_sp$SPID
AS SELECT
    dvid,
    _adomoid,
    fv_timescale_func(itime, 300, 0) AS timescale,
    f_user,
    srcip,
    srcintf,
    srcintfrole,
    dstip,
    dstintf,
    dstintfrole,
    dstcountry,
    policyid,
    policytype,
    maxState(avatar) AS avatar_state,
    maxState(epeuid) AS epeuid_state,
    groupArrayState(threat) AS threat_state,
    groupArrayState(threattype) AS threattype_state,
    groupArrayState(threatlevel) AS threatlevel_state,
    sumState(toInt64(threatweight)) AS threatweight_state,
    sumState(toInt64(threatblock)) AS threatblock_state,
    sumState(toInt64(incidents)) AS incident_state,
    sumState(toInt64(incident_block)) AS incident_block_state,
    sumState(toInt64(thwgt_cri)) AS thwgt_cri_state,
    sumState(toInt64(thwgt_hig)) AS thwgt_hig_state,
    sumState(toInt64(thwgt_med)) AS thwgt_med_state,
    sumState(toInt64(thwgt_low)) AS thwgt_low_state
    FROM (
       SELECT dvid, itime,
           _devlogtype,
           _adomoid,
           $LOGFIELD-user,
           `user` AS f_user,
           $LOGFIELD-srcip,
           $LOGFIELD-srcintf,
           $LOGFIELD-srcintfrole,
           $LOGFIELD-dstip,
           $LOGFIELD-dstintf,
           $LOGFIELD-dstintfrole,
           $LOGFIELD-dstcountry,
           $LOGFIELD-crscore,
           $LOGFIELD-fctuid,
           $LOGFIELD-unauthuser,
           $LOGFIELD-crlevel,
           (CASE WHEN fctuid IS NOT NULL AND unauthuser IS NOT NULL THEN CONCAT(toString(fctuid), ',', unauthuser) ELSE NULL END) AS avatar,
           ( CASE WHEN epid > 1023 AND euid != 0 THEN CONCAT(toString(epid), ',', toString(euid)) ELSE NULL END) AS epeuid,
           $LOGFIELD-threat,
           $LOGFIELD-threattype,
           $LOGFIELD-threatlevel,
           $LOGFIELD-policyid,
           $LOGFIELD-policytype,
           $LOGFIELD-msg,
           bitAnd(crscore, 65535) AS threatweight,
           bitAnd(crscore, 65535) AS threatblock,
           (CASE WHEN crlevel='critical' THEN crscore ELSE 0 END) AS thwgt_cri,
           (CASE WHEN crlevel='high'     THEN crscore ELSE 0 END) AS thwgt_hig,
           (CASE WHEN crlevel='medium'   THEN crscore ELSE 0 END) AS thwgt_med,
           (CASE WHEN crlevel='low'      THEN crscore ELSE 0 END) AS thwgt_low,
           1 AS incidents,
           1 AS incident_block
      FROM siem.ulog_sp$SPID
      WHERE threat IS NOT NULL AND _devlogtype = 1 AND msg LIKE 'anomaly%'
)
GROUP BY _adomoid, dvid, timescale,
         f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole, dstcountry, policyid, policytype,
         threat, threattype, threatlevel, policyid, policytype;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_a_src_dst_threat_hour_mv_sp$SPID
TO siem.fv_fgt_a_src_dst_threat_hour_sp$SPID
AS SELECT
    dvid,
    _adomoid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    f_user,
    srcip,
    srcintf,
    srcintfrole,
    dstip,
    dstintf,
    dstintfrole,
    dstcountry,
    policyid,
    policytype,
    maxState(avatar) AS avatar_state,
    maxState(epeuid) AS epeuid_state,
    groupArrayMergeState(threat_state) AS threat_state,
    groupArrayMergeState(threattype_state) AS threattype_state,
    groupArrayMergeState(threatlevel_state) AS threatlevel_state,
    sumState(threatweight) AS threatweight_state,
    sumState(threatblock) AS threatblock_state,
    sumState(incidents) AS incident_state,
    sumState(incident_block) AS incident_block_state,
    sumState(thwgt_cri) AS thwgt_cri_state,
    sumState(thwgt_hig) AS thwgt_hig_state,
    sumState(thwgt_med) AS thwgt_med_state,
    sumState(thwgt_low) AS thwgt_low_state
    FROM (
        SELECT
        dvid,
        _adomoid,
        timescale,
        f_user,
        srcip,
        srcintf,
        srcintfrole,
        dstip,
        dstintf,
        dstintfrole,
        dstcountry,
        policyid,
        policytype,
        maxMerge(avatar_state) AS avatar,
        maxMerge(epeuid_state) AS epeuid,
        groupArrayMergeState(threat_state) AS threat_state,
        groupArrayMergeState(threattype_state) AS threattype_state,
        groupArrayMergeState(threatlevel_state) AS threatlevel_state,
        sumMerge(threatweight_state) AS threatweight,
        sumMerge(threatblock_state) AS threatblock,
        sumMerge(incident_state) AS incidents,
        sumMerge(incident_block_state) AS incident_block,
        sumMerge(thwgt_cri_state) AS thwgt_cri,
        sumMerge(thwgt_hig_state) AS thwgt_hig,
        sumMerge(thwgt_med_state) AS thwgt_med,
        sumMerge(thwgt_low_state) AS thwgt_low
      FROM siem.fv_fgt_a_src_dst_threat_5min_sp$SPID
      GROUP BY _adomoid, dvid, srcintfrole, dstintfrole, timescale,
               f_user, srcip, srcintf, dstip, dstintf, dstintfrole, dstcountry, policyid, policytype
)
GROUP BY _adomoid, dvid, timescale,
         f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole, dstcountry, policyid, policytype;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_a_src_dst_threat_day_mv_sp$SPID
TO siem.fv_fgt_a_src_dst_threat_day_sp$SPID
AS SELECT
    dvid,
    _adomoid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    f_user,
    srcip,
    srcintf,
    srcintfrole,
    dstip,
    dstintf,
    dstintfrole,
    dstcountry,
    policyid,
    policytype,
    maxState(avatar) AS avatar_state,
    maxState(epeuid) AS epeuid_state,
    groupArrayMergeState(threat_state) AS threat_state,
    groupArrayMergeState(threattype_state) AS threattype_state,
    groupArrayMergeState(threatlevel_state) AS threatlevel_state,
    sumState(threatweight) AS threatweight_state,
    sumState(threatblock) AS threatblock_state,
    sumState(incidents) AS incident_state,
    sumState(incident_block) AS incident_block_state,
    sumState(thwgt_cri) AS thwgt_cri_state,
    sumState(thwgt_hig) AS thwgt_hig_state,
    sumState(thwgt_med) AS thwgt_med_state,
    sumState(thwgt_low) AS thwgt_low_state
    FROM (
        SELECT
        dvid,
        _adomoid,
        timescale,
        f_user,
        srcip,
        srcintf,
        srcintfrole,
        dstip,
        dstintf,
        dstintfrole,
        dstcountry,
        policyid,
        policytype,
        maxMerge(avatar_state) AS avatar,
        maxMerge(epeuid_state) AS epeuid,
        groupArrayMergeState(threat_state) AS threat_state,
        groupArrayMergeState(threattype_state) AS threattype_state,
        groupArrayMergeState(threatlevel_state) AS threatlevel_state,
        sumMerge(threatweight_state) AS threatweight,
        sumMerge(threatblock_state) AS threatblock,
        sumMerge(incident_state) AS incidents,
        sumMerge(incident_block_state) AS incident_block,
        sumMerge(thwgt_cri_state) AS thwgt_cri,
        sumMerge(thwgt_hig_state) AS thwgt_hig,
        sumMerge(thwgt_med_state) AS thwgt_med,
        sumMerge(thwgt_low_state) AS thwgt_low
      FROM siem.fv_fgt_a_src_dst_threat_hour_sp$SPID
      GROUP BY _adomoid, dvid, srcintfrole, dstintfrole, timescale,
               f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole, dstcountry, policyid, policytype
)
GROUP BY _adomoid, dvid, timescale,
         f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole, dstcountry, policyid, policytype;

ALTER TABLE siem.fv_fgt_a_src_dst_threat_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
