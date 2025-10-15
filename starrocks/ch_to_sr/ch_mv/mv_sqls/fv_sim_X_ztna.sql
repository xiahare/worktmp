/*
{
    "datasource_mv": "fv_sim_X_ztna_5min_mv_adom$ADOMOID",
    "version": "070601.3382",
    "type": "norm_all_adom_mv",
    "name": "fv_sim_X_ztna"
}
*/
DROP TABLE IF EXISTS siem.fv_sim_X_ztna_5min_mv_adom$ADOMOID;
DROP TABLE IF EXISTS siem.fv_sim_X_ztna_hour_mv_adom$ADOMOID;
DROP TABLE IF EXISTS siem.fv_sim_X_ztna_day_mv_adom$ADOMOID;
DROP TABLE IF EXISTS siem.fv_sim_X_ztna_5min_adom$ADOMOID;
DROP TABLE IF EXISTS siem.fv_sim_X_ztna_hour_adom$ADOMOID;
DROP TABLE IF EXISTS siem.fv_sim_X_ztna_day_adom$ADOMOID;

CREATE TABLE IF NOT EXISTS siem.fv_sim_X_ztna_5min_adom$ADOMOID (
    timescale DateTime, data_sourceid String,
    data_sourcevdom String,
    f_user Nullable(String),
    adom_oid UInt64,
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
PRIMARY KEY (adom_oid, timescale, data_sourceid, data_sourcevdom, f_user, srcip, dstip)
ORDER BY (adom_oid, timescale,  data_sourceid, data_sourcevdom,
          f_user, srcip, dstip, srcintf, dev_src, devtype, srcmac, dstintf, dstcountry,
          fctuid, accessproxy, saasname, app_group,
          policyname, policyid, policytype, service)

PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_sim_X_ztna_hour_adom$ADOMOID AS siem.fv_sim_X_ztna_5min_adom$ADOMOID;
CREATE TABLE IF NOT EXISTS siem.fv_sim_X_ztna_day_adom$ADOMOID AS siem.fv_sim_X_ztna_5min_adom$ADOMOID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_sim_X_ztna_5min_mv_adom$ADOMOID
TO siem.fv_sim_X_ztna_5min_adom$ADOMOID
AS SELECT
    adom_oid, data_sourceid,
    data_sourcevdom,
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
    sumState(toInt64(traffic_in)) AS traffic_in_state,
    sumState(toInt64(traffic_out)) AS traffic_out_state,
    sumState(session_block) AS session_block_state,
    sumState(sessions) AS sessions_state
    FROM (
       SELECT
        adom_oid, data_sourceid,
        data_sourcevdom,
        itime AS timescale,
        coalesce(nullifna(user_name), nullifna(user_unauthuser)) AS f_user,
        src_ip AS srcip, 
        src_intf as srcintf,
        src_mac AS srcmac,
        coalesce(src_domain, src_mac) AS dev_src,
        dst_ip AS dstip,
        dst_intf AS dstintf,
        dst_geo_country AS dstcountry,
        get_devtype(host_osver, host_osname, data_sourcetype) AS devtype,
        app_group_name(app_name) AS app_group,
        event_policyid AS policyid,
        event_policytype AS policytype,
        event_policy AS policyname,
        app_service AS service,
        json_extract(app_access, 'accessproxy') AS accessproxy,
        cloud_appname AS saasname,
        host_uid AS fctuid,
        sum(coalesce(net_sentdelta, net_sentbytes, 0)+coalesce(net_recvdelta, net_recvbytes, 0)) AS bandwidth,
        sum(coalesce(net_recvdelta, net_recvbytes, 0)) AS traffic_in,
        sum(coalesce(net_sentdelta, net_sentbytes, 0)) AS traffic_out,
        sum(CAST((CASE WHEN(bitAnd(logflag, 2) > 0) THEN 1 ELSE 0 END), 'Int64')) AS session_block, 
        sum(CAST((CASE WHEN(bitAnd(logflag, 1) > 0) THEN 1 ELSE 0 END), 'Int64')) AS sessions
      FROM $LOG
      WHERE event_type = 'traffic' AND accessproxy IS NOT NULL
      GROUP BY adom_oid, data_sourceid, data_sourcevdom, timescale,
               f_user, srcip, dstip, srcintf, dev_src, devtype, srcmac, dstintf, dstcountry,
               fctuid, accessproxy, saasname, app_group,
               policyname, policyid, policytype, service
)
GROUP BY adom_oid, data_sourceid, data_sourcevdom, timescale,
         f_user, srcip, dstip, srcintf, dev_src, devtype, srcmac, dstintf, dstcountry,
         fctuid, accessproxy, saasname, app_group,
         policyname, policyid, policytype, service;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_sim_X_ztna_hour_mv_adom$ADOMOID
TO siem.fv_sim_X_ztna_hour_adom$ADOMOID
AS SELECT
    adom_oid, data_sourceid,
    data_sourcevdom,
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
        adom_oid, data_sourceid,
        data_sourcevdom,
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
      FROM siem.fv_sim_X_ztna_5min_adom$ADOMOID
      GROUP BY adom_oid, data_sourceid, data_sourcevdom, timescale,
               f_user, srcip, dstip, srcintf, dev_src, devtype, srcmac, dstintf, dstcountry,
               fctuid, accessproxy, saasname, app_group,
               policyname, policyid, policytype, service
)
GROUP BY adom_oid, data_sourceid, data_sourcevdom, timescale,
         f_user, srcip, dstip, srcintf, dev_src, devtype, srcmac, dstintf, dstcountry,
         fctuid, accessproxy, saasname, app_group,
         policyname, policyid, policytype, service;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_sim_X_ztna_day_mv_adom$ADOMOID
TO siem.fv_sim_X_ztna_day_adom$ADOMOID
AS SELECT
    adom_oid, data_sourceid,
    data_sourcevdom,
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
        adom_oid, data_sourceid,
        data_sourcevdom,
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
      FROM siem.fv_sim_X_ztna_hour_adom$ADOMOID
      GROUP BY adom_oid, data_sourceid, data_sourcevdom, timescale,
               f_user, srcip, dstip, srcintf, dev_src, devtype, srcmac, dstintf, dstcountry,
               fctuid, accessproxy, saasname, app_group,
               policyname, policyid, policytype, service
)
GROUP BY adom_oid, data_sourceid, data_sourcevdom, timescale,
         f_user, srcip, dstip, srcintf, dev_src, devtype, srcmac, dstintf, dstcountry,
         fctuid, accessproxy, saasname, app_group,
         policyname, policyid, policytype, service;

ALTER TABLE siem.fv_sim_X_ztna_day_mv_adom$ADOMOID MODIFY COMMENT '$VERSION';
