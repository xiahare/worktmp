/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_t_ztna",
    "datasource_mv": "fv_fgt_t_ztna_5min_mv_sp$SPID",
    "datasource": "fv_fgt_t_src_dst"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_t_ztna_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_ztna_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_ztna_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_ztna_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_ztna_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_ztna_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_ztna_5min_sp$SPID (
    timescale DateTime, dvid Int32,
    f_user Nullable(String),
    _adomoid UInt64,
    dstintf LowCardinality(Nullable(String)),
    dstip Nullable(IPv6),
    dstcountry LowCardinality(Nullable(String)),
    srcip Nullable(IPv6),
    srcintf LowCardinality(Nullable(String)),
    srcmac Nullable(String),
    dev_src Nullable(String),
    app_group Nullable(String),
    policyid Nullable(UInt32),
    policytype LowCardinality(Nullable(String)),
    policyname Nullable(String),
    service LowCardinality(Nullable(String)),
    accessproxy Nullable(String),
    saasname Nullable(String),
    fctuid Nullable(UUID),
    bandwidth_state AggregateFunction(sum, Int64),
    devtype Nullable(String),
    traffic_in_state AggregateFunction(sum, Int64),
    traffic_out_state AggregateFunction(sum, Int64), 
    session_block_state AggregateFunction(sum, Int64),
    sessions_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, timescale, dvid, f_user, srcip, dstip)
ORDER BY (_adomoid, timescale,  dvid,
          f_user, srcip, dstip, srcintf, dev_src, devtype, srcmac, dstintf, dstcountry,
          fctuid, accessproxy, saasname, app_group,
          policyname, policyid, policytype, service)

PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_ztna_hour_sp$SPID AS siem.fv_fgt_t_ztna_5min_sp$SPID;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_ztna_day_sp$SPID AS siem.fv_fgt_t_ztna_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_ztna_5min_mv_sp$SPID
TO siem.fv_fgt_t_ztna_5min_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    f_user,
    srcip, 
    srcintf,
    srcmac,
    dev_src,
    dstip,
    dstintf,
    dstcountry,
    devtype,
    app_group,
    policyid,
    policytype,
    policyname,
    accessproxy,
    saasname,
    fctuid,
    sumState(toInt64(bandwidth)) AS bandwidth_state,
    sumState(traffic_in) AS traffic_in_state,
    sumState(traffic_out) AS traffic_out_state,
    sumState(session_block) AS session_block_state,
    sumState(sessions) AS sessions_state
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        f_user,
        srcip, 
        srcintf,
        srcmac,
        dev_src,
        dstip,
        dstintf,
        dstcountry,
        devtype,
        app_group,
        policyid,
        policytype,
        policyname,
        service,
        accessproxy,
        saasname,
        fctuid,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(traffic_out_state) AS traffic_out,
        sumMerge(session_block_state) AS session_block,
        sumMerge(sessions_state) AS sessions
      FROM siem.fv_fgt_t_src_dst_5min_sp$SPID
      WHERE accessproxy IS NOT NULL
      GROUP BY _adomoid, dvid, timescale,
               f_user, srcip, dstip, srcintf, dev_src, devtype, srcmac, dstintf, dstcountry,
               fctuid, accessproxy, saasname, app_group,
               policyname, policyid, policytype, service
)
GROUP BY _adomoid, dvid, timescale,
         f_user, srcip, dstip, srcintf, dev_src, devtype, srcmac, dstintf, dstcountry,
         fctuid, accessproxy, saasname, app_group,
         policyname, policyid, policytype, service;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_ztna_hour_mv_sp$SPID
TO siem.fv_fgt_t_ztna_hour_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    f_user,
    srcip, 
    srcintf, 
    srcmac,
    dev_src,
    dstip,
    dstintf,
    dstcountry,
    devtype,
    app_group,
    policyid,
    policytype,
    policyname,
    service,
    accessproxy,
    saasname,
    fctuid,
    sumState(bandwidth) AS bandwidth_state,
    sumState(traffic_in) AS traffic_in_state,
    sumState(traffic_out) AS traffic_out_state,
    sumState(session_block) AS session_block_state,
    sumState(sessions) AS sessions_state
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        f_user,
        srcip, 
        srcintf,
        srcmac,
        dev_src,
        dstip,
        dstintf,
        dstcountry,
        devtype,
        app_group,
        policyid,
        policytype,
        policyname,
        service,
        accessproxy,
        saasname,
        fctuid,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(traffic_out_state) AS traffic_out,
        sumMerge(session_block_state) AS session_block,
        sumMerge(sessions_state) AS sessions
      FROM siem.fv_fgt_t_ztna_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale,
               f_user, srcip, dstip, srcintf, dev_src, devtype, srcmac, dstintf, dstcountry,
               fctuid, accessproxy, saasname, app_group,
               policyname, policyid, policytype, service
)
GROUP BY _adomoid, dvid, timescale,
         f_user, srcip, dstip, srcintf, dev_src, devtype, srcmac, dstintf, dstcountry,
         fctuid, accessproxy, saasname, app_group,
         policyname, policyid, policytype, service;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_ztna_day_mv_sp$SPID
TO siem.fv_fgt_t_ztna_day_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    f_user,
    srcip, 
    srcintf,
    srcmac,
    dev_src,
    dstip,
    dstintf,
    dstcountry,
    devtype,
    app_group,
    policyid,
    policytype,
    policyname,
    service,
    accessproxy,
    saasname,
    fctuid,
    sumState(bandwidth) AS bandwidth_state,
    sumState(traffic_in) AS traffic_in_state,
    sumState(traffic_out) AS traffic_out_state,
    sumState(session_block) AS session_block_state,
    sumState(sessions) AS sessions_state
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        f_user,
        srcip, 
        srcintf,
        srcmac,
        dev_src,
        dstip,
        dstintf,
        dstcountry,
        devtype,
        app_group,
        policyid,
        policytype,
        policyname,
        service,
        accessproxy,
        saasname,
        fctuid,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(traffic_out_state) AS traffic_out,
        sumMerge(session_block_state) AS session_block,
        sumMerge(sessions_state) AS sessions
      FROM siem.fv_fgt_t_ztna_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale,
               f_user, srcip, dstip, srcintf, dev_src, devtype, srcmac, dstintf, dstcountry,
               fctuid, accessproxy, saasname, app_group,
               policyname, policyid, policytype, service
)
GROUP BY _adomoid, dvid, timescale,
         f_user, srcip, dstip, srcintf, dev_src, devtype, srcmac, dstintf, dstcountry,
         fctuid, accessproxy, saasname, app_group,
         policyname, policyid, policytype, service;

ALTER TABLE siem.fv_fgt_t_ztna_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
