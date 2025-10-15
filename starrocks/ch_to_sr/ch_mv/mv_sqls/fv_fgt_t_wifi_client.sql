/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_t_wifi_client",
    "datasource_mv": "fv_fgt_t_wifi_client_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_t_wifi_client_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_wifi_client_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_wifi_client_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_wifi_client_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_wifi_client_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_wifi_client_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_wifi_client_5min_sp$SPID (
    _adomoid UInt64,
    dvid Int32,
    timescale DateTime,
    srcintfrole LowCardinality(Nullable(String)),
    dstintfrole LowCardinality(Nullable(String)),
    user_src Nullable(String),
    mac Nullable(String),
    hostname_mac Nullable(String),
    devtype_state AggregateFunction(max, Nullable(String)),
    srcip_state AggregateFunction(max, Nullable(IPv6)),
    app_group Nullable(String),
    d_flags UInt32,
    ap Nullable(String),
    apsn Nullable(String),
    srcssid Nullable(String),
    bandwidth_state AggregateFunction(sum, Int64),
    traffic_out_state AggregateFunction(sum, Int64),
    traffic_in_state AggregateFunction(sum, Int64),
    session_block_state AggregateFunction(sum, Int64),
    sessions_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, user_src)
ORDER BY (_adomoid, dvid, timescale,
          user_src, mac, hostname_mac,
          app_group, d_flags, ap, apsn, srcssid)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;


CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_wifi_client_hour_sp$SPID AS siem.fv_fgt_t_wifi_client_5min_sp$SPID;


CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_wifi_client_day_sp$SPID AS siem.fv_fgt_t_wifi_client_5min_sp$SPID;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_wifi_client_5min_mv_sp$SPID
TO siem.fv_fgt_t_wifi_client_5min_sp$SPID
AS SELECT 
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    srcintfrole,
    dstintfrole,
    user_src,
    mac,
    hostname_mac,
    maxState(devtype) AS devtype_state,
    maxState(srcip) AS srcip_state,
    app_group,
    d_flags,
    ap,
    apsn,
    srcssid,
    sumState(toInt64(bandwidth)) AS bandwidth_state,
    sumState(toInt64(traffic_out)) AS traffic_out_state,
    sumState(toInt64(traffic_in)) AS traffic_in_state,
    sumState(toInt64(session_block)) AS session_block_state,
    sumState(toInt64(sessions)) AS sessions_state
FROM (
      SELECT
        _adomoid,
        dvid,
        itime AS timescale,
        srcintfrole,
        dstintfrole,
        $LOGFIELD-user,
        $LOGFIELD-unauthuser,
        $LOGFIELD-collectedemail,
        $LOGFIELD-srcip,
        coalesce(nullifna(`user`), nullifna(`unauthuser`), nullifna(`collectedemail`), ipstr(`srcip`)) AS user_src,
        $LOGFIELD-srcmac,
        coalesce_str(`srcmac`, ipstr(`srcip`)) AS mac,
        $LOGFIELD-srcname,
        coalesce(nullifna(`srcname`), `srcmac`) AS hostname_mac,
        $LOGFIELD-app,
        app_group_name(app) as app_group,
        $LOGFIELD-appcat,
        (CASE WHEN appcat='unscanned' THEN 1 ELSE 0 END) AS d_flags,
        $LOGFIELD-ap,
        $LOGFIELD-apsn,
        $LOGFIELD-srcssid,
        $LOGFIELD-srcintfrole,
        $LOGFIELD-dstintfrole,
        $LOGFIELD-devtype,
        $LOGFIELD-sentbyte,
        $LOGFIELD-rcvdbyte,
        $LOGFIELD-sentdelta,
        $LOGFIELD-rcvddelta,
        coalesce(sentdelta, sentbyte, 0) + coalesce(rcvddelta, rcvdbyte, 0) AS bandwidth,
        coalesce(rcvddelta, rcvdbyte, 0) AS traffic_in,
        coalesce(sentdelta, sentbyte, 0) AS traffic_out,
        CAST(( CASE WHEN(bitAnd(logflag, 2) > 0) THEN 1 ELSE 0 END), 'Int64') AS session_block,
        CAST(( CASE WHEN(bitAnd(logflag, 1) > 0) THEN 1 ELSE 0 END), 'Int64') AS sessions
      FROM siem.tlog_sp$SPID
      WHERE bitAnd(logflag, bitOr(1, 32)) > 0
            AND srcssid IS NOT NULL
            AND hostname_mac IS NOT NULL AND srcssid IS NOT NULL
            AND _devlogtype = 10
)
GROUP BY _adomoid, dvid, timescale, srcintfrole, dstintfrole,
         user_src, mac, hostname_mac,
         app_group, d_flags, ap, apsn, srcssid
HAVING sum(coalesce(sentdelta, sentbyte, 0) + coalesce(rcvddelta, rcvdbyte, 0)) > 0;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_wifi_client_hour_mv_sp$SPID
TO siem.fv_fgt_t_wifi_client_hour_sp$SPID
AS SELECT 
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    srcintfrole,
    dstintfrole,
    user_src,
    mac,
    hostname_mac,
    maxState(devtype) AS devtype_state,
    maxState(srcip) AS srcip_state,
    app_group,
    d_flags,
    ap,
    apsn,
    srcssid,
    sumState(bandwidth) AS bandwidth_state,
    sumState(traffic_out) AS traffic_out_state,
    sumState(traffic_in) AS traffic_in_state,
    sumState(session_block) AS session_block_state,
    sumState(sessions) AS sessions_state
FROM (
      SELECT
        _adomoid,
        dvid,
        timescale,
        srcintfrole,
        dstintfrole,
        user_src,
        mac,
        hostname_mac,
        maxMerge(devtype_state) AS devtype,
        maxMerge(srcip_state) AS srcip,
        app_group,
        d_flags,
        ap,
        apsn,
        srcssid,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_out_state) AS traffic_out,
        sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(session_block_state) AS session_block,
        sumMerge(sessions_state) AS sessions
      FROM siem.fv_fgt_t_wifi_client_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale, srcintfrole, dstintfrole,
               user_src, mac, hostname_mac,
               app_group, d_flags, ap, apsn, srcssid
)
GROUP BY _adomoid, dvid, timescale, srcintfrole, dstintfrole,
         user_src, mac, hostname_mac,
         app_group, d_flags, ap, apsn, srcssid;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_wifi_client_day_mv_sp$SPID
TO siem.fv_fgt_t_wifi_client_day_sp$SPID
AS SELECT 
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    srcintfrole,
    dstintfrole,
    user_src,
    mac,
    hostname_mac,
    maxState(devtype) AS devtype_state,
    maxState(srcip) AS srcip_state,
    app_group,
    d_flags,
    ap,
    apsn,
    srcssid,
    sumState(bandwidth) AS bandwidth_state,
    sumState(traffic_out) AS traffic_out_state,
    sumState(traffic_in) AS traffic_in_state,
    sumState(session_block) AS session_block_state,
    sumState(sessions) AS sessions_state
FROM (
      SELECT
        _adomoid,
        dvid,
        timescale,
        srcintfrole,
        dstintfrole,
        user_src,
        mac,
        hostname_mac,
        maxMerge(devtype_state) AS devtype,
        maxMerge(srcip_state) AS srcip,
        app_group,
        d_flags,
        ap,
        apsn,
        srcssid,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_out_state) AS traffic_out,
        sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(session_block_state) AS session_block,
        sumMerge(sessions_state) AS sessions
      FROM siem.fv_fgt_t_wifi_client_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale, srcintfrole, dstintfrole,
               user_src, mac, hostname_mac,
               app_group, d_flags, ap, apsn, srcssid
)
GROUP BY _adomoid, dvid, timescale, srcintfrole, dstintfrole,
         user_src, mac, hostname_mac,
         app_group, d_flags, ap, apsn, srcssid;

ALTER TABLE siem.fv_fgt_t_wifi_client_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
