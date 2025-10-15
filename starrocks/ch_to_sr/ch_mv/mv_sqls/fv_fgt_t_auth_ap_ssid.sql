/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_t_auth_ap_ssid",
    "datasource_mv": "fv_fgt_t_auth_ap_ssid_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_t_auth_ap_ssid_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_auth_ap_ssid_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_auth_ap_ssid_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_auth_ap_ssid_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_auth_ap_ssid_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_auth_ap_ssid_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_auth_ap_ssid_5min_sp$SPID (
    timescale DateTime, dvid Int32,
    _adomoid UInt64,
    user_src Nullable(String),
    ap Nullable(String),
    srcip Nullable(IPv6),
    srcssid Nullable(String),
    hostname_mac Nullable(String),
    channel Nullable(UInt32),
    bandwidth_state AggregateFunction(sum, Int64), traffic_in_state AggregateFunction(sum, Int64),
    traffic_out_state AggregateFunction(sum, Int64), session_block_state AggregateFunction(sum, Int64),
    sessions_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, user_src, ap, srcip)
ORDER BY (_adomoid, dvid, timescale, 
          user_src, ap, srcip, srcssid, hostname_mac, channel)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;


CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_auth_ap_ssid_hour_sp$SPID AS siem.fv_fgt_t_auth_ap_ssid_5min_sp$SPID;


CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_auth_ap_ssid_day_sp$SPID AS siem.fv_fgt_t_auth_ap_ssid_5min_sp$SPID;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_auth_ap_ssid_5min_mv_sp$SPID
TO siem.fv_fgt_t_auth_ap_ssid_5min_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(itime, 300, 0) AS timescale,
       user_src,
       ap, srcip, srcssid, 
       hostname_mac, channel,
       sumState(toInt64(bandwidth)) AS bandwidth_state, sumState(toInt64(traffic_in)) AS traffic_in_state,
       sumState(toInt64(traffic_out)) AS traffic_out_state, sumState(toInt64(session_block)) AS session_block_state,
       sumState(toInt64(sessions)) AS sessions_state
    FROM (
       SELECT
           itime,
           dvid,
           _adomoid,
           _devlogtype,
           $LOGFIELD-srcip,
           $LOGFIELD-user,
           $LOGFIELD-unauthuser,
           $LOGFIELD-ap,
           $LOGFIELD-srcssid,
           $LOGFIELD-channel,
           $LOGFIELD-srcname,
           $LOGFIELD-srcmac,
           $LOGFIELD-sentbyte,
           $LOGFIELD-rcvdbyte, 
           $LOGFIELD-sentdelta,
           $LOGFIELD-rcvddelta,
           coalesce(nullifna(`user`), nullifna(`unauthuser`), ipstr(`srcip`)) AS user_src,
           coalesce(nullifna(`srcname`), `srcmac`) AS hostname_mac,
           coalesce(sentdelta, sentbyte, 0)+coalesce(rcvddelta, rcvdbyte, 0) AS bandwidth,
           coalesce(rcvddelta, rcvdbyte, 0) AS traffic_in,
           coalesce(sentdelta, sentbyte, 0) AS traffic_out,
           CAST(( CASE WHEN(bitAnd(logflag, 2) > 0) THEN 1 ELSE 0 END), 'Int64') AS session_block, 
           CAST(( CASE WHEN(bitAnd(logflag, 1) > 0) THEN 1 ELSE 0 END), 'Int64') AS sessions
      FROM siem.tlog_sp$SPID
      WHERE srcssid IS NOT NULL AND ap IS NOT NULL AND _devlogtype = 10
)
GROUP BY _adomoid, dvid, timescale, user_src, ap, srcip, srcssid, hostname_mac, channel
HAVING sum(coalesce(sentdelta, sentbyte, 0) + coalesce(rcvddelta, rcvdbyte, 0)) > 0;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_auth_ap_ssid_hour_mv_sp$SPID
TO siem.fv_fgt_t_auth_ap_ssid_hour_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 3600, 0) AS timescale,
       user_src,
       ap, srcip, srcssid, 
       hostname_mac, channel,
       sumState(bandwidth) AS bandwidth_state, sumState(traffic_in) AS traffic_in_state,
       sumState(traffic_out) AS traffic_out_state, sumState(session_block) AS session_block_state,
       sumState(sessions) AS sessions_state
FROM (
    SELECT
        _adomoid, dvid, timescale,
        user_src, ap, srcip, srcssid, hostname_mac, channel,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(traffic_out_state) AS traffic_out,
        sumMerge(session_block_state) AS session_block,
        sumMerge(sessions_state) AS sessions
    FROM siem.fv_fgt_t_auth_ap_ssid_5min_sp$SPID
    GROUP BY  _adomoid, dvid, timescale, user_src, ap, srcip, srcssid, hostname_mac, channel
)
GROUP BY  _adomoid, dvid, timescale, user_src, ap, srcip, srcssid, hostname_mac, channel;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_auth_ap_ssid_day_mv_sp$SPID
TO siem.fv_fgt_t_auth_ap_ssid_day_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 28800, 0) AS timescale,
       user_src,
       ap, srcip, srcssid, 
       hostname_mac, channel,
       sumState(bandwidth) AS bandwidth_state, sumState(traffic_in) AS traffic_in_state,
       sumState(traffic_out) AS traffic_out_state, sumState(session_block) AS session_block_state,
       sumState(sessions) AS sessions_state
FROM (
    SELECT
        _adomoid, dvid, timescale,
        user_src, ap, srcip, srcssid, hostname_mac, channel,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(traffic_out_state) AS traffic_out,
        sumMerge(session_block_state) AS session_block,
        sumMerge(sessions_state) AS sessions
    FROM siem.fv_fgt_t_auth_ap_ssid_hour_sp$SPID
    GROUP BY  _adomoid, dvid, timescale, user_src, ap, srcip, srcssid, hostname_mac, channel
)
GROUP BY  _adomoid, dvid, timescale, user_src, ap, srcip, srcssid, hostname_mac, channel;

ALTER TABLE siem.fv_fgt_t_auth_ap_ssid_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
