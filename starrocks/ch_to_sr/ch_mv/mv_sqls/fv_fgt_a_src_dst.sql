/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_a_src_dst",
    "datasource_mv": "fv_fgt_a_src_dst_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_a_src_dst_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_src_dst_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_src_dst_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_src_dst_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_src_dst_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_src_dst_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_a_src_dst_5min_sp$SPID (
    dvid Int32,
    timescale DateTime,
    domain Nullable(String),
    catdesc LowCardinality(Nullable(String)),
    f_user Nullable(String),
    _adomoid UInt64,
    epid Nullable(Int32),
    srcmac Nullable(String),
    srcip Nullable(IPv6),
    srcintf LowCardinality(Nullable(String)),
    srcintfrole LowCardinality(Nullable(String)),
    dev_src Nullable(String),
    dstip Nullable(IPv6),
    dstintf LowCardinality(Nullable(String)),
    dstintfrole LowCardinality(Nullable(String)),
    dstcountry Nullable(String),
    policymode LowCardinality(Nullable(String)),
    policyid Nullable(UInt32),
    policytype LowCardinality(Nullable(String)),
    poluuid Nullable(UUID),
    avatar_state  AggregateFunction(max, Nullable(String)),
    epeuid_state  AggregateFunction(max, Nullable(String)),
    crlevel_state AggregateFunction(max, Int8),
    threatweight_state AggregateFunction(sum, Int64),
    threatblock_state AggregateFunction(sum, Int64),
    thwgt_cri_state AggregateFunction(sum, Int64),
    thwgt_hig_state AggregateFunction(sum, Int64),
    thwgt_med_state AggregateFunction(sum, Int64),
    thwgt_low_state AggregateFunction(sum, Int64),
    incident_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, srcintfrole, dstintfrole)
ORDER BY (_adomoid, dvid, timescale, srcintfrole, dstintfrole, catdesc, epid, f_user, domain, srcip, srcmac,
         srcintf, dstip, dstintf, policyid, policytype)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_a_src_dst_hour_sp$SPID AS siem.fv_fgt_a_src_dst_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_a_src_dst_day_sp$SPID AS siem.fv_fgt_a_src_dst_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_a_src_dst_5min_mv_sp$SPID
TO siem.fv_fgt_a_src_dst_5min_sp$SPID
AS SELECT
    dvid,
    catdesc,
    fv_timescale_func(itime, 300, 0) AS timescale,
    domain,
    f_user,
    _adomoid,
    epid,
    srcip,
    srcmac,
    srcintf,
    srcintfrole,
    dev_src,
    dstip,
    dstintf,
    dstintfrole,
    dstcountry,
    policymode,
    policyid,
    policytype,
    poluuid,
    maxState(avatar) AS avatar_state,
    maxState(epeuid) AS epeuid_state,
    maxState(toInt8(crlevel_i)) AS crlevel_state,
    sumState(toInt64(crscore)) AS threatweight_state,
    sumState(toInt64(crscore)) AS threatblock_state,
    sumState(toInt64(thwgt_cri)) AS thwgt_cri_state,
    sumState(toInt64(thwgt_hig)) AS thwgt_hig_state,
    sumState(toInt64(thwgt_med)) AS thwgt_med_state,
    sumState(toInt64(thwgt_low)) AS thwgt_low_state,
    sumState(toInt64(incident)) AS incident_state
    FROM (
       SELECT dvid,
           coalesce(nullifna(`user`), nullifna(`unauthuser`)) AS f_user,
           itime, dtime,
           (CASE WHEN epid<1024 THEN NULL ELSE epid END) AS epid,
           euid,
           _devlogtype,
           _adomoid,
           '' AS catdesc,
           $LOGFIELD-user,
           $LOGFIELD-msg,
           $LOGFIELD-srcmac,
           $LOGFIELD-srcip,
           $LOGFIELD-srcintf,
           $LOGFIELD-srcintfrole,
           $LOGFIELD-srcname,
           coalesce(srcname, srcmac) AS dev_src,
           $LOGFIELD-dstip,
           $LOGFIELD-dstintf,
           $LOGFIELD-dstintfrole,
           $LOGFIELD-dstcountry,
           $LOGFIELD-policyid,
           $LOGFIELD-policytype,
           $LOGFIELD-unauthuser,
           $LOGFIELD-crlevel,
           $LOGFIELD-crscore-_crscore,
           $LOGFIELD-fctuid,
           $LOGFIELD-policymode,
           $LOGFIELD-policyid,
           $LOGFIELD-policytype,
           $LOGFIELD-poluuid,
           '' AS domain,
           (CASE WHEN fctuid IS NOT NULL AND unauthuser IS NOT NULL THEN CONCAT(toString(fctuid), ',', unauthuser) ELSE NULL END) AS avatar,
           (CASE WHEN epid > 1023 AND euid != 0 THEN CONCAT(toString(epid), ',', toString(euid)) ELSE NULL END) AS epeuid,
           (CASE WHEN crlevel='critical' THEN crscore ELSE 0 END) AS thwgt_cri,
           (CASE WHEN crlevel='high'     THEN crscore ELSE 0 END) AS thwgt_hig,
           (CASE WHEN crlevel='medium'   THEN crscore ELSE 0 END) AS thwgt_med,
           (CASE WHEN crlevel='low'      THEN crscore ELSE 0 END) AS thwgt_low,
           threat_level_s2i(crlevel) AS crlevel_i,
           1 AS incident,
           bitAnd(coalesce(_crscore, 0), 65535) AS crscore
      FROM siem.ulog_sp$SPID
      WHERE _devlogtype = 1 AND msg LIKE 'anomaly%'
)
GROUP BY _adomoid, dvid, catdesc, timescale, epid, domain, f_user,
         srcmac, srcip, srcintf, srcintfrole, dev_src,
         dstip, dstintf, dstintfrole, dstcountry,
         policymode, policyid, policytype, poluuid;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_a_src_dst_hour_mv_sp$SPID
TO siem.fv_fgt_a_src_dst_hour_sp$SPID
AS SELECT
    dvid,
    catdesc,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    domain,
    f_user,
    _adomoid,
    epid,
    srcmac,
    srcip,
    srcintf,
    srcintfrole,
    dev_src,
    dstip,
    dstintf,
    dstintfrole,
    dstcountry,
    policymode,
    policyid,
    policytype,
    poluuid,
    maxState(avatar) AS avatar_state,
    maxState(epeuid) AS epeuid_state,
    maxState(crlevel_i) AS crlevel_state,
    sumState(threatweight) AS threatweight_state,
    sumState(threatblock) AS threatblock_state,
    sumState(thwgt_cri) AS thwgt_cri_state,
    sumState(thwgt_hig) AS thwgt_hig_state,
    sumState(thwgt_med) AS thwgt_med_state,
    sumState(thwgt_low) AS thwgt_low_state,
    sumState(incidents) AS incident_state
    FROM (
        SELECT
        dvid,
        catdesc,
        timescale,
        domain,
        f_user,
        _adomoid,
        epid,
        srcmac,
        srcip,
        srcintf,
        srcintfrole,
        dev_src,
        dstip,
        dstintf,
        dstintfrole,
        dstcountry,
        policymode,
        policyid,
        policytype,
        poluuid,
        maxMerge(avatar_state) AS avatar,
        maxMerge(epeuid_state) AS epeuid,
        maxMerge(crlevel_state) AS crlevel_i,
        sumMerge(threatweight_state) AS threatweight,
        sumMerge(threatblock_state) AS threatblock,
        sumMerge(thwgt_cri_state) AS thwgt_cri,
        sumMerge(thwgt_hig_state) AS thwgt_hig,
        sumMerge(thwgt_med_state) AS thwgt_med,
        sumMerge(thwgt_low_state) AS thwgt_low,
        sumMerge(incident_state) AS incidents
      FROM siem.fv_fgt_a_src_dst_5min_sp$SPID
      GROUP BY _adomoid, dvid, catdesc, timescale, epid, domain, f_user,
             srcmac, srcip, srcintf, srcintfrole, dev_src,
             dstip, dstintf, dstintfrole, dstcountry,
             policymode, policyid, policytype, poluuid
)
GROUP BY _adomoid, dvid, catdesc, timescale, epid, domain, f_user,
         srcmac, srcip, srcintf, srcintfrole, dev_src,
         dstip, dstintf, dstintfrole, dstcountry,
         policymode, policyid, policytype, poluuid;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_a_src_dst_day_mv_sp$SPID
TO siem.fv_fgt_a_src_dst_day_sp$SPID
AS SELECT
    dvid,
    catdesc,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    domain,
    f_user,
    _adomoid,
    epid,
    srcmac,
    srcip,
    srcintf,
    srcintfrole,
    dev_src,
    dstip,
    dstintf,
    dstintfrole,
    dstcountry,
    policymode,
    policyid,
    policytype,
    poluuid,
    maxState(avatar) AS avatar_state,
    maxState(epeuid) AS epeuid_state,
    maxState(crlevel_i) AS crlevel_state,
    sumState(threatweight) AS threatweight_state,
    sumState(threatblock) AS threatblock_state,
    sumState(thwgt_cri) AS thwgt_cri_state,
    sumState(thwgt_hig) AS thwgt_hig_state,
    sumState(thwgt_med) AS thwgt_med_state,
    sumState(thwgt_low) AS thwgt_low_state,
    sumState(incidents) AS incident_state
    FROM (
        SELECT
        dvid,
        catdesc,
        timescale,
        domain,
        f_user,
        _adomoid,
        epid,
        srcmac,
        srcip,
        srcintf,
        srcintfrole,
        dev_src,
        dstip,
        dstintf,
        dstintfrole,
        dstcountry,
        policymode,
        policyid,
        policytype,
        poluuid,
        maxMerge(avatar_state) AS avatar,
        maxMerge(epeuid_state) AS epeuid,
        maxMerge(crlevel_state) AS crlevel_i,
        sumMerge(threatweight_state) AS threatweight,
        sumMerge(threatblock_state) AS threatblock,
        sumMerge(thwgt_cri_state) AS thwgt_cri,
        sumMerge(thwgt_hig_state) AS thwgt_hig,
        sumMerge(thwgt_med_state) AS thwgt_med,
        sumMerge(thwgt_low_state) AS thwgt_low,
        sumMerge(incident_state) AS incidents
      FROM siem.fv_fgt_a_src_dst_hour_sp$SPID
      GROUP BY _adomoid, dvid, catdesc, timescale, epid, domain, f_user,
             srcmac, srcip, srcintf, srcintfrole, dev_src,
             dstip, dstintf, dstintfrole, dstcountry,
             policymode, policyid, policytype, poluuid
)
GROUP BY _adomoid, dvid, catdesc, timescale, epid, domain, f_user,
         srcmac, srcip, srcintf, srcintfrole, dev_src,
         dstip, dstintf, dstintfrole, dstcountry,
         policymode, policyid, policytype, poluuid;

ALTER TABLE siem.fv_fgt_a_src_dst_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
