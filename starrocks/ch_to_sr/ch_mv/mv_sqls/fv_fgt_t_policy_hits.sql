/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_t_policy_hits",
    "datasource_mv": "fv_fgt_t_policy_hits_5min_mv_sp$SPID",
    "datasource": "fv_fgt_t_src_dst"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_t_policy_hits_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_policy_hits_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_policy_hits_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_policy_hits_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_policy_hits_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_policy_hits_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_policy_hits_5min_sp$SPID (
    timescale DateTime, dvid Int32,
    f_user Nullable(String),
    _adomoid UInt64,
    srcintfrole LowCardinality(Nullable(String)),
    dstintfrole LowCardinality(Nullable(String)),
    policyid Nullable(UInt32),
    policytype LowCardinality(Nullable(String)),
    poluuid Nullable(UUID),
    policyname Nullable(String),
    accessproxy Nullable(String),
    srcip Nullable(IPv6),
    srcintf LowCardinality(Nullable(String)),
    srcuuid Nullable(UUID),
    dstip Nullable(IPv6),
    dstintf LowCardinality(Nullable(String)),
    dstuuid Nullable(UUID),
    dstcountry Nullable(String),
    app_group Nullable(String),
    service LowCardinality(Nullable(String)),
    catdesc LowCardinality(Nullable(String)),
    domain Nullable(String),
    thwgt_cri_state AggregateFunction(sum, Int64),
    thwgt_hig_state AggregateFunction(sum, Int64),
    thwgt_med_state AggregateFunction(sum, Int64),
    thwgt_low_state AggregateFunction(sum, Int64),
    bandwidth_state AggregateFunction(sum, Int64),
    traffic_in_state AggregateFunction(sum, Int64),
    traffic_out_state AggregateFunction(sum, Int64),
    count_block_state AggregateFunction(sum, Int64),
    counts_state AggregateFunction(sum, Int64),
    logtime_state AggregateFunction(max, DateTime)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, timescale, dvid, srcintfrole, dstintfrole, policyid,
             policytype, poluuid, policyname, f_user)
ORDER BY (_adomoid, timescale,  dvid,
          srcintfrole, dstintfrole,
          policyid, policytype, poluuid, policyname, f_user, accessproxy)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_policy_hits_hour_sp$SPID AS siem.fv_fgt_t_policy_hits_5min_sp$SPID;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_policy_hits_day_sp$SPID AS siem.fv_fgt_t_policy_hits_5min_sp$SPID;
CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_policy_hits_5min_mv_sp$SPID
TO siem.fv_fgt_t_policy_hits_5min_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    srcintfrole,
    dstintfrole,
    policyid,
    policytype,
    poluuid,
    policyname,
    accessproxy,
    f_user, srcip, srcintf, srcuuid, dstip, dstintf, dstuuid, dstcountry,
    app_group, service, catdesc, domain,
    sumState(thwgt_cri) AS thwgt_cri_state,
    sumState(thwgt_hig) AS thwgt_hig_state,
    sumState(thwgt_med) AS thwgt_med_state,
    sumState(thwgt_low) AS thwgt_low_state,
    sumState(bandwidth) AS bandwidth_state,
    sumState(traffic_in) AS traffic_in_state,
    sumState(traffic_out) AS traffic_out_state,
    sumState(session_block) AS count_block_state,
    sumState(sessions) AS counts_state,
    maxState(logtime) AS logtime_state
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        srcintfrole,
        dstintfrole,
        policyid,
        policytype,
        poluuid,
        policyname,
        accessproxy,
        f_user, srcip, srcintf, srcuuid, dstip, dstintf, dstuuid, dstcountry,
        app_group, service, catdesc, domain,
        sumMerge(thwgt_cri_state) AS thwgt_cri,
        sumMerge(thwgt_hig_state) AS thwgt_hig,
        sumMerge(thwgt_med_state) AS thwgt_med,
        sumMerge(thwgt_low_state) AS thwgt_low,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(traffic_out_state) AS traffic_out,
        sumMerge(session_block_state) AS session_block,
        sumMerge(sessions_state) AS sessions,
        maxMerge(logtime_state) AS logtime
      FROM siem.fv_fgt_t_src_dst_5min_sp$SPID
      WHERE policyid IS NOT NULL
      GROUP BY _adomoid, dvid, timescale,
               srcintfrole, dstintfrole,
               policyid, policytype, poluuid, policyname, f_user, accessproxy,
               srcip, srcintf, srcuuid, dstip, dstintf, dstuuid, dstcountry,
               app_group, service, catdesc, domain
)
GROUP BY _adomoid, dvid, timescale,
         srcintfrole, dstintfrole,
         policyid, policytype, poluuid, policyname, f_user, accessproxy,
         srcip, srcintf, srcuuid, dstip, dstintf, dstuuid, dstcountry,
         app_group, service, catdesc, domain;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_policy_hits_hour_mv_sp$SPID
TO siem.fv_fgt_t_policy_hits_hour_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    srcintfrole,
    dstintfrole,
    policyid,
    policytype,
    poluuid,
    policyname,
    accessproxy,
    f_user, srcip, srcintf, srcuuid, dstip, dstintf, dstuuid, dstcountry,
    app_group, service, catdesc, domain,
    sumState(thwgt_cri) AS thwgt_cri_state,
    sumState(thwgt_hig) AS thwgt_hig_state,
    sumState(thwgt_med) AS thwgt_med_state,
    sumState(thwgt_low) AS thwgt_low_state,
    sumState(bandwidth) AS bandwidth_state,
    sumState(traffic_in) AS traffic_in_state,
    sumState(traffic_out) AS traffic_out_state,
    sumState(count_block) AS count_block_state,
    sumState(counts) AS counts_state,
    maxState(logtime) AS logtime_state
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        srcintfrole,
        dstintfrole,
        policyid,
        policytype,
        poluuid,
        policyname,
        accessproxy,
        f_user, srcip, srcintf, srcuuid, dstip, dstintf, dstuuid, dstcountry,
        app_group, service, catdesc, domain,
        sumMerge(thwgt_cri_state) AS thwgt_cri,
        sumMerge(thwgt_hig_state) AS thwgt_hig,
        sumMerge(thwgt_med_state) AS thwgt_med,
        sumMerge(thwgt_low_state) AS thwgt_low,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(traffic_out_state) AS traffic_out,
        sumMerge(count_block_state) AS count_block,
        sumMerge(counts_state) AS counts,
        maxMerge(logtime_state) AS logtime
      FROM siem.fv_fgt_t_policy_hits_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale,
               srcintfrole, dstintfrole,
               policyid, policytype, poluuid, policyname, f_user, accessproxy,
               srcip, srcintf, srcuuid, dstip, dstintf, dstuuid, dstcountry,
               app_group, service, catdesc, domain
)
GROUP BY _adomoid, dvid, timescale,
         srcintfrole, dstintfrole,
         policyid, policytype, poluuid, policyname, f_user, accessproxy,
         srcip, srcintf, srcuuid, dstip, dstintf, dstuuid, dstcountry,
         app_group, service, catdesc, domain;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_policy_hits_day_mv_sp$SPID
TO siem.fv_fgt_t_policy_hits_day_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    srcintfrole,
    dstintfrole,
    policyid,
    policytype,
    poluuid,
    policyname,
    accessproxy,
    f_user, srcip, srcintf, srcuuid, dstip, dstintf, dstuuid, dstcountry,
    app_group, service, catdesc, domain,
    sumState(thwgt_cri) AS thwgt_cri_state,
    sumState(thwgt_hig) AS thwgt_hig_state,
    sumState(thwgt_med) AS thwgt_med_state,
    sumState(thwgt_low) AS thwgt_low_state,
    sumState(bandwidth) AS bandwidth_state,
    sumState(traffic_in) AS traffic_in_state,
    sumState(traffic_out) AS traffic_out_state,
    sumState(count_block) AS count_block_state,
    sumState(counts) AS counts_state,
    maxState(logtime) AS logtime_state
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        srcintfrole,
        dstintfrole,
        policyid,
        policytype,
        poluuid,
        policyname,
        accessproxy,
        f_user, srcip, srcintf, srcuuid, dstip, dstintf, dstuuid, dstcountry,
        app_group, service, catdesc, domain,
        sumMerge(thwgt_cri_state) AS thwgt_cri,
        sumMerge(thwgt_hig_state) AS thwgt_hig,
        sumMerge(thwgt_med_state) AS thwgt_med,
        sumMerge(thwgt_low_state) AS thwgt_low,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(traffic_out_state) AS traffic_out,
        sumMerge(count_block_state) AS count_block,
        sumMerge(counts_state) AS counts,
        maxMerge(logtime_state) AS logtime
      FROM siem.fv_fgt_t_policy_hits_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale,
               srcintfrole, dstintfrole,
               policyid, policytype, poluuid, policyname, f_user, accessproxy,
               srcip, srcintf, srcuuid, dstip, dstintf, dstuuid, dstcountry,
               app_group, service, catdesc, domain
)
GROUP BY _adomoid, dvid, timescale,
         srcintfrole, dstintfrole,
         policyid, policytype, poluuid, policyname, f_user, accessproxy,
         srcip, srcintf, srcuuid, dstip, dstintf, dstuuid, dstcountry,
         app_group, service, catdesc, domain;

ALTER TABLE siem.fv_fgt_t_policy_hits_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
