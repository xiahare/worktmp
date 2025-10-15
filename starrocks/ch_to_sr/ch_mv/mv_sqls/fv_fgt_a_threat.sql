/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_a_threat",
    "datasource_mv": "fv_fgt_a_threat_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_a_threat_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_threat_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_threat_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_threat_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_threat_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_threat_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_a_threat_5min_sp$SPID (
    dvid Int32,
    _adomoid UInt64,
    timescale DateTime,
    threat_s LowCardinality(Nullable(String)),
    threattype_s LowCardinality(Nullable(String)),
    threatlevel_s Nullable(Int32),
    f_user Nullable(String),
    srcmac Nullable(String),
    srcip Nullable(IPv6),
    srcintf LowCardinality(Nullable(String)),
    srcintfrole LowCardinality(Nullable(String)),
    srccountry Nullable(String),
    dstip Nullable(IPv6),
    dstintf LowCardinality(Nullable(String)),
    dstintfrole LowCardinality(Nullable(String)),
    dstcountry Nullable(String),
    policymode LowCardinality(Nullable(String)),
    policyid Nullable(UInt32),
    policytype LowCardinality(Nullable(String)),
    poluuid Nullable(UUID),
    threatweight_state AggregateFunction(sum, Nullable(Int64)),
    threatblock_state AggregateFunction(sum, Nullable(Int64)),
    thwgt_cri_state AggregateFunction(sum, Nullable(Int64)),
    thwgt_hig_state AggregateFunction(sum, Nullable(Int64)),
    thwgt_med_state AggregateFunction(sum, Nullable(Int64)),
    thwgt_low_state AggregateFunction(sum, Nullable(Int64)),
    incident_block_state AggregateFunction(sum, Int64),
    incident_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, threat_s, threattype_s, threatlevel_s, f_user, srcmac, srcip)
ORDER BY (_adomoid, dvid, timescale,
          threat_s, threattype_s, threatlevel_s,
          f_user, srcmac, srcip, srcintf, srcintfrole, srccountry, dstip, dstintf, dstintfrole, dstcountry)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_a_threat_hour_sp$SPID AS siem.fv_fgt_a_threat_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_a_threat_day_sp$SPID AS siem.fv_fgt_a_threat_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_a_threat_5min_mv_sp$SPID
TO siem.fv_fgt_a_threat_5min_sp$SPID
AS SELECT
    dvid,
    _adomoid,
    fv_timescale_func(itime, 300, 0) AS timescale,
    threat_s,
    threattype_s,
    threatlevel_s,
    f_user,
    srcmac,
    srcip,
    srcintf,
    srcintfrole,
    srccountry,
    dstip,
    dstintf,
    dstintfrole,
    dstcountry,
    policymode, policyid, policytype, poluuid,
    sumState(toInt64(threatweight)) AS threatweight_state,
    sumState(toInt64(threatblock)) AS threatblock_state,
    sumState(toInt64(thwgt_cri)) AS thwgt_cri_state,
    sumState(toInt64(thwgt_hig)) AS thwgt_hig_state,
    sumState(toInt64(thwgt_med)) AS thwgt_med_state,
    sumState(toInt64(thwgt_low)) AS thwgt_low_state,
    sumState(toInt64(incidents)) AS incident_state,
    sumState(toInt64(incident_block)) AS incident_block_state
    FROM (
       SELECT dvid, itime,
           _devlogtype,
           _adomoid,
           $LOGFIELD-msg,
           $LOGFIELD-user,
           `user` AS f_user,
           $LOGFIELD-threat-threat_s,
           $LOGFIELD-threattype-threattype_s,
           $LOGFIELD-threatlevel-threatlevel_s,
           $LOGFIELD-srcmac,
           $LOGFIELD-srcip,
           $LOGFIELD-srcintf,
           $LOGFIELD-srcintfrole,
           $LOGFIELD-srccountry,
           $LOGFIELD-dstip,
           $LOGFIELD-dstintf,
           $LOGFIELD-dstintfrole,
           $LOGFIELD-dstcountry,
           $LOGFIELD-policymode,
           $LOGFIELD-policyid,
           $LOGFIELD-policytype,
           $LOGFIELD-poluuid,
           (CASE WHEN threatlevel_s=4 THEN bitAnd(crscore, 65535) ELSE 0 END) AS thwgt_cri,
           (CASE WHEN threatlevel_s=3 THEN bitAnd(crscore, 65535) ELSE 0 END) AS thwgt_hig,
           (CASE WHEN threatlevel_s=2 THEN bitAnd(crscore, 65535) ELSE 0 END) AS thwgt_med,
           (CASE WHEN threatlevel_s=1 THEN bitAnd(crscore, 65535) ELSE 0 END) AS thwgt_low,
           $LOGFIELD-crscore,
           bitAnd(crscore, 65535) AS threatweight,
           bitAnd(crscore, 65535) AS threatblock,
           1 AS incidents,
           1 AS incident_block
      FROM siem.ulog_sp$SPID
      WHERE threat_s IS NOT NULL AND _devlogtype = 1 AND msg LIKE 'anomaly%'
)
GROUP BY _adomoid, dvid, timescale, threat_s, threattype_s, threatlevel_s, f_user,
         srcmac, srcip, srcintf, srcintfrole, srccountry, 
         dstip, dstintf, dstintfrole, dstcountry,
         policymode, policyid, policytype, poluuid;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_a_threat_hour_mv_sp$SPID
TO siem.fv_fgt_a_threat_hour_sp$SPID
AS SELECT
    dvid,
    _adomoid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    threat_s,
    threattype_s,
    threatlevel_s,
    f_user,
    srcmac,
    srcip,
    srcintf,
    srcintfrole,
    srccountry,
    dstip,
    dstintf,
    dstintfrole,
    dstcountry,
    policymode, policyid, policytype, poluuid,
    sumState(threatweight) AS threatweight_state,
    sumState(threatblock) AS threatblock_state,
    sumState(toInt64(thwgt_cri)) AS thwgt_cri_state,
    sumState(toInt64(thwgt_hig)) AS thwgt_hig_state,
    sumState(toInt64(thwgt_med)) AS thwgt_med_state,
    sumState(toInt64(thwgt_low)) AS thwgt_low_state,
    sumState(toInt64(incidents)) AS incident_state,
    sumState(toInt64(incident_block)) AS incident_block_state
    FROM (
        SELECT
        dvid,
        _adomoid,
        timescale,
        threat_s,
        threattype_s,
        threatlevel_s,
        f_user,
        srcmac,
        srcip,
        srcintf,
        srcintfrole,
        srccountry,
        dstip,
        dstintf,
        dstintfrole,
        dstcountry,
        policymode, policyid, policytype, poluuid,
        sumMerge(threatweight_state) AS threatweight,
        sumMerge(threatblock_state) AS threatblock,
        sumMerge(thwgt_cri_state) AS thwgt_cri,
        sumMerge(thwgt_hig_state) AS thwgt_hig,
        sumMerge(thwgt_med_state) AS thwgt_med,
        sumMerge(thwgt_low_state) AS thwgt_low,
        sumMerge(incident_state) AS incidents,
        sumMerge(incident_block_state) AS incident_block
      FROM siem.fv_fgt_a_threat_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale, threat_s, threattype_s, threatlevel_s, f_user,
               srcmac, srcip, srcintf, srcintfrole, srccountry,
               dstip, dstintf, dstintfrole, dstcountry,
               policymode, policyid, policytype, poluuid
)
GROUP BY _adomoid, dvid, timescale, threat_s, threattype_s, threatlevel_s, f_user,
         srcmac, srcip, srcintf, srcintfrole, srccountry,
         dstip, dstintf, dstintfrole, dstcountry,
         policymode, policyid, policytype, poluuid;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_a_threat_day_mv_sp$SPID
TO siem.fv_fgt_a_threat_day_sp$SPID
AS SELECT
    dvid,
    _adomoid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    threat_s,
    threattype_s,
    threatlevel_s,
    f_user,
    srcmac,
    srcip,
    srcintf,
    srcintfrole,
    srccountry,
    dstip,
    dstintf,
    dstintfrole,
    dstcountry,
    policymode, policyid, policytype, poluuid,
    sumState(toInt64(threatweight)) AS threatweight_state,
    sumState(toInt64(threatblock)) AS threatblock_state,
    sumState(toInt64(thwgt_cri)) AS thwgt_cri_state,
    sumState(toInt64(thwgt_hig)) AS thwgt_hig_state,
    sumState(toInt64(thwgt_med)) AS thwgt_med_state,
    sumState(toInt64(thwgt_low)) AS thwgt_low_state,
    sumState(toInt64(incidents)) AS incident_state,
    sumState(toInt64(incident_block)) AS incident_block_state
    FROM (
        SELECT
        dvid,
        _adomoid,
        timescale,
        threat_s,
        threattype_s,
        threatlevel_s,
        f_user,
        srcmac,
        srcip,
        srcintf,
        srcintfrole,
        srccountry,
        dstip,
        dstintf,
        dstintfrole,
        dstcountry,
        policymode, policyid, policytype, poluuid,
        sumMerge(threatweight_state) AS threatweight,
        sumMerge(threatblock_state) AS threatblock,
        sumMerge(thwgt_cri_state) AS thwgt_cri,
        sumMerge(thwgt_hig_state) AS thwgt_hig,
        sumMerge(thwgt_med_state) AS thwgt_med,
        sumMerge(thwgt_low_state) AS thwgt_low,
        sumMerge(incident_state) AS incidents,
        sumMerge(incident_block_state) AS incident_block
      FROM siem.fv_fgt_a_threat_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale, threat_s, threattype_s, threatlevel_s, f_user,
               srcmac, srcip, srcintf, srcintfrole, srccountry,
               dstip, dstintf, dstintfrole, dstcountry,
               policymode, policyid, policytype, poluuid
)
GROUP BY _adomoid, dvid, timescale, threat_s, threattype_s, threatlevel_s, f_user,
         srcmac, srcip, srcintf, srcintfrole, srccountry,
         dstip, dstintf, dstintfrole, dstcountry,
         policymode, policyid, policytype, poluuid;

ALTER TABLE siem.fv_fgt_a_threat_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
