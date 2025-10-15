/*
{
    "type": "sp_mv",
    "version": "070600.3453",
    "name": "fv_fgt_e_wifi_bridge_mode",
    "datasource_mv": "fv_fgt_e_wifi_bridge_mode_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_e_wifi_bridge_mode_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_wifi_bridge_mode_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_wifi_bridge_mode_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_wifi_bridge_mode_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_wifi_bridge_mode_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_wifi_bridge_mode_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_wifi_bridge_mode_5min_sp$SPID (
    _adomoid UInt64,
    dvid Int32,
    timescale DateTime,
    srcintfrole LowCardinality(Nullable(String)),
    dstintfrole LowCardinality(Nullable(String)),
    user_src Nullable(String),
    mac Nullable(String),
    srcip Nullable(IPv6),
    hostname_mac Nullable(String),
    ap Nullable(String),
    apsn Nullable(String),
    srcssid Nullable(String),
    bandwidth_state AggregateFunction(sum, Int64),
    traffic_out_state AggregateFunction(sum, Nullable(Int64)),
    traffic_in_state AggregateFunction(sum, Nullable(Int64))
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, srcintfrole, dstintfrole, user_src)
ORDER BY (_adomoid, dvid, timescale, srcintfrole, dstintfrole, user_src, mac, ap, apsn, srcssid, srcip, hostname_mac)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;


CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_wifi_bridge_mode_hour_sp$SPID AS siem.fv_fgt_e_wifi_bridge_mode_5min_sp$SPID;


CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_wifi_bridge_mode_day_sp$SPID AS siem.fv_fgt_e_wifi_bridge_mode_5min_sp$SPID;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_wifi_bridge_mode_5min_mv_sp$SPID
TO siem.fv_fgt_e_wifi_bridge_mode_5min_sp$SPID
AS SELECT 
    _adomoid,
    dvid,
    fv_timescale_func(itime, 300, 0) AS timescale,
    srcintfrole,
    dstintfrole,
    user_src,
    stamac as mac,
    srcip,
    stamac as hostname_mac,
    ap,
    apsn,
    srcssid,
    sumState(toInt64(coalesce(sentdelta, 0) + coalesce(rcvddelta, 0))) AS bandwidth_state,
    sumState(toInt64(sentbyte-sentdelta)) AS traffic_out_state,
    sumState(toInt64(rcvdbyte-rcvddelta)) AS traffic_in_state
FROM (
      SELECT
        _adomoid,
        dvid,
        itime,
        $LOGFIELD-stamac,
        $LOGFIELD-mac,
        $LOGFIELD-devtype,
        $LOGFIELD-user,
        $LOGFIELD-srcip,
        $LOGFIELD-ap,
        $LOGFIELD-sn,
        sn AS apsn,
        $LOGFIELD-ssid,
        ssid AS srcssid,
        dtime,
        $LOGFIELD-action,
        $LOGFIELD-sentbyte,
        $LOGFIELD-rcvdbyte,
        $LOGFIELD-srcname,
        $LOGFIELD-srcmac,
        $LOGFIELD-srcintfrole,
        $LOGFIELD-dstintfrole,
        lagInFrame(coalesce(sentbyte, 0)) OVER (PARTITION BY stamac ORDER BY itime) AS sentdelta,
        lagInFrame(coalesce(rcvdbyte, 0)) OVER (PARTITION BY stamac ORDER BY itime) AS rcvddelta,
        coalesce(nullifna(`user`), ipstr(srcip)) AS user_src
      FROM siem.elog_sp$SPID
      WHERE subtype = 'wireless' AND stamac IS NOT NULL AND ssid IS NOT NULL
            AND action IN ('sta-wl-bridge-traffic-stats', 'reasssoc-req', 'assoc-req')
            AND _devlogtype = 5
)
GROUP BY _adomoid, dvid, timescale, srcintfrole, dstintfrole,
         user_src, stamac, ap, apsn, srcssid, srcip;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_wifi_bridge_mode_hour_mv_sp$SPID
TO siem.fv_fgt_e_wifi_bridge_mode_hour_sp$SPID
AS SELECT 
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    srcintfrole,
    dstintfrole,
    user_src,
    srcip,
    mac,
    hostname_mac,
    ap,
    apsn,
    srcssid,
    sumState(bandwidth) AS bandwidth_state,
    sumState(traffic_out) AS traffic_out_state,
    sumState(traffic_in) AS traffic_in_state
FROM (
      SELECT
        _adomoid,
        dvid,
        timescale,
        srcintfrole,
        dstintfrole,
        user_src,
        mac,
        srcip,
        hostname_mac,
        ap,
        apsn,
        srcssid,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_out_state) AS traffic_out,
        sumMerge(traffic_in_state) AS traffic_in
      FROM siem.fv_fgt_e_wifi_bridge_mode_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale, srcintfrole, dstintfrole,
               user_src, mac, ap, apsn, srcssid, srcip, hostname_mac
)
GROUP BY _adomoid, dvid, timescale, srcintfrole, dstintfrole,
         user_src, mac, ap, apsn, srcssid, srcip, hostname_mac;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_wifi_bridge_mode_day_mv_sp$SPID
TO siem.fv_fgt_e_wifi_bridge_mode_day_sp$SPID
AS SELECT 
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    srcintfrole,
    dstintfrole,
    user_src,
    srcip,
    mac,
    hostname_mac,
    ap,
    apsn,
    srcssid,
    sumState(bandwidth) AS bandwidth_state,
    sumState(traffic_out) AS traffic_out_state,
    sumState(traffic_in) AS traffic_in_state
FROM (
      SELECT
        _adomoid,
        dvid,
        timescale,
        srcintfrole,
        dstintfrole,
        user_src,
        mac,
        srcip,
        hostname_mac,
        ap,
        apsn,
        srcssid,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_out_state) AS traffic_out,
        sumMerge(traffic_in_state) AS traffic_in
      FROM siem.fv_fgt_e_wifi_bridge_mode_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale, srcintfrole, dstintfrole,
               user_src, mac, ap, apsn, srcssid, srcip, hostname_mac
)
GROUP BY _adomoid, dvid, timescale, srcintfrole, dstintfrole,
         user_src, mac, ap, apsn, srcssid, srcip, hostname_mac;

ALTER TABLE siem.fv_fgt_e_wifi_bridge_mode_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
