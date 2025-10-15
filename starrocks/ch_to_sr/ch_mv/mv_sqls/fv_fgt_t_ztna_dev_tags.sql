/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_t_ztna_dev_tags",
    "datasource_mv": "fv_fgt_t_ztna_dev_tags_5min_mv_sp$SPID",
    "datasource": "fv_fgt_t_src_dst"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_t_ztna_dev_tags_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_ztna_dev_tags_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_ztna_dev_tags_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_ztna_dev_tags_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_ztna_dev_tags_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_ztna_dev_tags_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_ztna_dev_tags_5min_sp$SPID (
    timescale DateTime, dvid Int32,
    f_user Nullable(String),
    _adomoid UInt64,
    dev_tag Nullable(String),
    dstintf LowCardinality(Nullable(String)),
    dstip Nullable(IPv6),
    srcip Nullable(IPv6),
    srcintf LowCardinality(Nullable(String)),
    srcmac Nullable(String),
    policyid Nullable(UInt32),
    policytype LowCardinality(Nullable(String)),
    policyname Nullable(String),
    accessproxy Nullable(String),
    dev_src  Nullable(String),
    devtype Nullable(String),
    count_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, timescale, dvid, accessproxy, dev_tag, dev_src, devtype, f_user)
ORDER BY (_adomoid, timescale,  dvid,
          accessproxy, dev_tag, dev_src, devtype, f_user,
          srcip, srcintf, srcmac, dstip, dstintf,
          policyname, policyid, policytype)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_ztna_dev_tags_hour_sp$SPID AS siem.fv_fgt_t_ztna_dev_tags_5min_sp$SPID;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_ztna_dev_tags_day_sp$SPID AS siem.fv_fgt_t_ztna_dev_tags_5min_sp$SPID;
CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_ztna_dev_tags_5min_mv_sp$SPID
TO siem.fv_fgt_t_ztna_dev_tags_5min_sp$SPID
AS SELECT
    _adomoid, dvid,
    dev_tag,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    f_user,
    srcip, 
    srcintf, 
    srcmac,
    dev_src,
    dstip,
    dstintf,
    devtype,
    policyid,
    policytype,
    policyname,
    accessproxy,
    sumState(toInt64(count)) AS count_state
    FROM (
       SELECT
        _adomoid, dvid,
        dev_tag,
        timescale,
        f_user,
        srcip, 
        srcintf,
        srcmac,
        dev_src,
        dstip,
        dstintf,
        devtype,
        policyid,
        policytype,
        policyname,
        accessproxy,
        arrayJoin(splitByChar('/', coalesce(clientdevicetags,''))) AS dev_tag,
        count(*) AS count
      FROM siem.fv_fgt_t_src_dst_5min_sp$SPID
      WHERE accessproxy IS NOT NULL AND clientdevicetags IS NOT NULL
      GROUP BY _adomoid, dvid, timescale,
               accessproxy, dev_tag, dev_src, devtype, f_user,
               srcip, srcintf, srcmac, dstip, dstintf,
               policyname, policyid, policytype
)
GROUP BY _adomoid, dvid, timescale,
         accessproxy, dev_tag, dev_src, devtype, f_user,
         srcip, srcintf, srcmac, dstip, dstintf,
         policyname, policyid, policytype;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_ztna_dev_tags_hour_mv_sp$SPID
TO siem.fv_fgt_t_ztna_dev_tags_hour_sp$SPID
AS SELECT
    _adomoid, dvid,
    dev_tag,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    f_user,
    srcip, 
    srcintf,
    srcmac,
    dev_src,
    dstip,
    dstintf,
    devtype,
    policyid,
    policytype,
    policyname,
    accessproxy,
    sumState(count) AS count_state
    FROM (
       SELECT
        _adomoid, dvid,
        dev_tag,
        timescale,
        f_user,
        srcip, 
        srcintf,
        srcmac,
        dev_src,
        dstip,
        dstintf,
        devtype,
        policyid,
        policytype,
        policyname,
        accessproxy,
        sumMerge(count_state) AS count
      FROM siem.fv_fgt_t_ztna_dev_tags_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale,
               accessproxy, dev_tag, dev_src, devtype, f_user,
               srcip, srcintf, srcmac, dstip, dstintf,
               policyname, policyid, policytype
)
GROUP BY _adomoid, dvid, timescale,
         accessproxy, dev_tag, dev_src, devtype, f_user,
         srcip, srcintf, srcmac, dstip, dstintf,
         policyname, policyid, policytype;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_ztna_dev_tags_day_mv_sp$SPID
TO siem.fv_fgt_t_ztna_dev_tags_day_sp$SPID
AS SELECT
    _adomoid, dvid,
    dev_tag,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    f_user,
    srcip, 
    srcintf,
    srcmac,
    dev_src,
    dstip,
    dstintf,
    devtype,
    policyid,
    policytype,
    policyname,
    accessproxy,
    sumState(count) AS count_state
    FROM (
       SELECT
        _adomoid, dvid,
        dev_tag,
        timescale,
        f_user,
        srcip, 
        srcintf, 
        srcmac,
        dev_src,
        dstip,
        dstintf,
        devtype,
        policyid,
        policytype,
        policyname,
        accessproxy,
        sumMerge(count_state) AS count
      FROM siem.fv_fgt_t_ztna_dev_tags_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale,
               accessproxy, dev_tag, dev_src, devtype, f_user,
               srcip, srcintf, srcmac, dstip, dstintf,
               policyname, policyid, policytype
)
GROUP BY _adomoid, dvid, timescale,
         accessproxy, dev_tag, dev_src, devtype, f_user,
         srcip, srcintf, srcmac, srcmac, dstip, dstintf,
         policyname, policyid, policytype;

ALTER TABLE siem.fv_fgt_t_ztna_dev_tags_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
