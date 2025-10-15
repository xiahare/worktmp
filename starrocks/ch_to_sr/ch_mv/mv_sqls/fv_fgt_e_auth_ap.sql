/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_e_auth_ap",
    "datasource_mv": "fv_fgt_e_auth_ap_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_e_auth_ap_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_auth_ap_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_auth_ap_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_auth_ap_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_auth_ap_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_auth_ap_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_auth_ap_5min_sp$SPID (
       timescale DateTime,
       dvid Int32,
       _adomoid UInt64,
       user_src Nullable(String),
       ap Nullable(String),
       hostname_mac Nullable(String),
       channel Nullable(UInt32),
       ssid Nullable(String),
       events_state AggregateFunction(sum, Int64)
  
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, user_src, ap)
ORDER BY (_adomoid, dvid, timescale, user_src, ap, hostname_mac, channel, ssid)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;


CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_auth_ap_hour_sp$SPID AS siem.fv_fgt_e_auth_ap_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_auth_ap_day_sp$SPID AS siem.fv_fgt_e_auth_ap_5min_sp$SPID;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_auth_ap_5min_mv_sp$SPID
TO siem.fv_fgt_e_auth_ap_5min_sp$SPID
AS SELECT 
       fv_timescale_func(timescale, 300, 0) AS timescale,
       dvid,
       _adomoid,
       user_src, ap, hostname_mac, channel, ssid,
       sumState(toInt64(events)) events_state
    FROM (
       SELECT
           itime as timescale, _devlogtype,
           dvid,
           _adomoid,
           ipstr($LOGFIELD_NOALIAS-srcip) AS srcip,
           srcip AS user_src,
           $LOGFIELD-ap-hostname_mac,
           $LOGFIELD-channel,
           $LOGFIELD-ap,
           $LOGFIELD-ssid,
           1 AS events
      FROM siem.elog_sp$SPID
      WHERE ssid IS NOT NULL AND ap IS NOT NULL AND NOT is_Zero_IPv6(srcip)
              AND _devlogtype = 5
)
GROUP BY _adomoid, dvid, timescale, user_src, ap, hostname_mac, channel, ssid;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_auth_ap_hour_mv_sp$SPID
TO siem.fv_fgt_e_auth_ap_hour_sp$SPID
AS SELECT
       fv_timescale_func(timescale, 3600, 0) AS timescale,
       dvid,
       _adomoid,
       user_src, ap, hostname_mac, channel, ssid,
       sumState(events) AS events_state
FROM (
    SELECT
       timescale,
       dvid,
       _adomoid,
       user_src, ap, hostname_mac, channel, ssid,
       sumMerge(events_state) AS events
    FROM siem.fv_fgt_e_auth_ap_5min_sp$SPID
    GROUP BY _adomoid, dvid, timescale, user_src, ap, hostname_mac, channel, ssid
)
GROUP BY _adomoid, dvid, timescale, user_src, ap, hostname_mac, channel, ssid;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_auth_ap_day_mv_sp$SPID
TO siem.fv_fgt_e_auth_ap_day_sp$SPID
AS SELECT
       fv_timescale_func(timescale, 28800, 0) AS timescale,
       dvid,
       _adomoid,
       user_src, ap, hostname_mac, channel, ssid,
       sumState(events) AS events_state
FROM (
    SELECT
       timescale,
       dvid,
       _adomoid,
       user_src, ap, hostname_mac, channel, ssid,
       sumMerge(events_state) AS events
    FROM siem.fv_fgt_e_auth_ap_hour_sp$SPID
    GROUP BY _adomoid, dvid, timescale, user_src, ap, hostname_mac, channel, ssid
)
GROUP BY _adomoid, dvid, timescale, user_src, ap, hostname_mac, channel, ssid;

ALTER TABLE siem.fv_fgt_e_auth_ap_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
