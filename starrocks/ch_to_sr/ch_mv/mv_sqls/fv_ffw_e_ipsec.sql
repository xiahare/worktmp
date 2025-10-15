/*
{
    "type": "sp_mv",
    "version": "070600.3335",
    "name": "fv_ffw_e_ipsec",
    "datasource_mv": "fv_ffw_e_ipsec_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_ffw_e_ipsec_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_ffw_e_ipsec_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_ffw_e_ipsec_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_ffw_e_ipsec_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_ffw_e_ipsec_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_ffw_e_ipsec_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_ffw_e_ipsec_5min_sp$SPID (
       timescale DateTime,
       dvid Int32,
       _adomoid UInt64,
       vpnusergroup Nullable(String),
       xauthuser Nullable(String),
       user Nullable(String),
       vpnname Nullable(String),
       remip Nullable(IPv6),
       locip Nullable(IPv6),
       tunneltype Nullable(String),
       tunnelid Nullable(UInt32),
       vpntype Int8,
       vpntunnel LowCardinality(Nullable(String)),
       s_time_state AggregateFunction(min, DateTime),
       e_time_state AggregateFunction(max, DateTime),
       max_duration_state AggregateFunction(max, Nullable(Int32)),
       min_duration_state AggregateFunction(min, Nullable(Int32)),
       traffic_out_state AggregateFunction(sum, Nullable(Int64)),
       traffic_in_state AggregateFunction(sum, Nullable(Int64))
  
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, vpnusergroup, xauthuser)
ORDER BY (_adomoid, dvid, timescale, vpnusergroup, xauthuser,
          user, vpnname,  remip, locip, tunneltype, tunnelid, vpntunnel, vpntype)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;


CREATE TABLE IF NOT EXISTS siem.fv_ffw_e_ipsec_hour_sp$SPID AS siem.fv_ffw_e_ipsec_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_ffw_e_ipsec_day_sp$SPID AS siem.fv_ffw_e_ipsec_5min_sp$SPID;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_ffw_e_ipsec_5min_mv_sp$SPID
TO siem.fv_ffw_e_ipsec_5min_sp$SPID
AS SELECT 
       fv_timescale_func(timescale, 300, 0) AS timescale,
       dvid,
       _adomoid,
       vpnusergroup,
       xauthuser,
       user,
       vpnname,
       remip,
       locip,
       tunneltype,
       tunnelid,
       vpntunnel,
       vpntype,
       minState(dtime) AS s_time_state,
       maxState(dtime) AS e_time_state, 
       maxState(toInt32(duration)) AS max_duration_state,
       minState(toInt32(duration)) AS min_duration_state,
       sumState(toInt64((case when sentdelta>0 then sentdelta else 0 end))) AS traffic_out_state,
       sumState(toInt64((case when rcvddelta>0 then rcvddelta else 0 end))) AS traffic_in_state
    FROM (
       SELECT
           itime as timescale,
           dvid,
           _adomoid,
           $LOGFIELD-group,
           vpn_trim(vpntunnel) AS vpnname,
           $LOGFIELD-remip,
           $LOGFIELD-locip,
           $LOGFIELD-tunneltype-_tunneltype,
           $LOGFIELD-tunnelid,
           $LOGFIELD-vpntunnel,
           dtime,
           $LOGFIELD-duration,
           $LOGFIELD-sentbyte,
           $LOGFIELD-rcvdbyte,
           $LOGFIELD-tunnelip,
           $LOGFIELD-action,
           $LOGFIELD-xauthgroup,
           $LOGFIELD-eventtime,
           nullifna($LOGFIELD_NOALIAS-xauthuser) AS xauthuser,
           nullifna($LOGFIELD_NOALIAS-user) AS user,
           (CASE WHEN _tunneltype LIKE 'ipsec%' THEN 'ipsec' ELSE _tunneltype END) AS tunneltype,
           (CASE WHEN tunneltype LIKE 'ssl%' OR NOT (tunnelip IS NULL OR ((is_Zero_IPv6(tunnelip) OR tunnelip = '0.0.0.0') AND logver IS NOT NULL)) THEN 0 ELSE 1 END) AS vpntype,
           coalesce(nullifna(`group`), nullifna(xauthgroup)) AS vpnusergroup,
           sentbyte-lagInFrame(coalesce(sentbyte, 0)) OVER (PARTITION BY dvid, tunnelid ORDER BY eventtime ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) AS sentdelta,
           rcvdbyte-lagInFrame(coalesce(rcvdbyte, 0)) OVER (PARTITION BY dvid, tunnelid ORDER BY eventtime ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) AS rcvddelta
      FROM siem.elog_sp$SPID
      WHERE subtype = 'vpn'
              AND (tunneltype LIKE 'ssl%' OR tunneltype LIKE 'ipsec%')
              AND action IN ('tunnel-stats', 'tunnel-down', 'tunnel-up')
              AND tunnelid IS NOT NULL AND tunnelid!=0
              AND _devlogtype = 21005
)
GROUP BY _adomoid, dvid, timescale, vpnusergroup, xauthuser,
    user, vpnname,  remip, locip, tunneltype, tunnelid, vpntunnel, vpntype;



CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_ffw_e_ipsec_hour_mv_sp$SPID
TO siem.fv_ffw_e_ipsec_hour_sp$SPID
AS SELECT
       fv_timescale_func(timescale, 3600, 0) AS timescale,
       dvid,
       _adomoid,
       vpnusergroup,
       xauthuser,
       user,
       vpnname,
       remip,
       locip,
       tunneltype,
       tunnelid,
       vpntunnel,
       vpntype,
       minState(s_time) AS s_time_state,
       maxState(e_time) AS e_time_state, 
       maxState(max_duration) AS max_duration_state,
       minState(min_duration) AS min_duration_state,
       sumState(traffic_out) AS traffic_out_state,
       sumState(traffic_in) AS traffic_in_state
FROM (
    SELECT
       timescale,
       dvid,
       _adomoid,
       vpnusergroup,
       xauthuser,
       user,
       vpnname,
       remip,
       locip,
       tunneltype,
       tunnelid,
       vpntunnel,
       vpntype,
       minMerge(s_time_state) AS s_time,
       maxMerge(e_time_state) AS e_time,
       maxMerge(max_duration_state) AS max_duration,
       minMerge(min_duration_state) AS min_duration,
       sumMerge(traffic_out_state) AS traffic_out,
       sumMerge(traffic_in_state) AS traffic_in
    FROM siem.fv_ffw_e_ipsec_5min_sp$SPID
    GROUP BY _adomoid, dvid, timescale, vpnusergroup, xauthuser,
        user, vpnname,  remip, locip, tunneltype, tunnelid, vpntunnel, vpntype
)
GROUP BY _adomoid, dvid, timescale, vpnusergroup, xauthuser,
    user, vpnname,  remip, locip, tunneltype, tunnelid, vpntunnel, vpntype;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_ffw_e_ipsec_day_mv_sp$SPID
TO siem.fv_ffw_e_ipsec_day_sp$SPID
AS SELECT
       fv_timescale_func(timescale, 28800, 0) AS timescale,
       dvid,
       _adomoid,
       vpnusergroup,
       xauthuser,
       user,
       vpnname,
       remip,
       locip,
       tunneltype,
       tunnelid,
       vpntunnel,
       vpntype,
       minState(s_time) AS s_time_state,
       maxState(e_time) AS e_time_state, 
       maxState(max_duration) AS max_duration_state,
       minState(min_duration) AS min_duration_state,
       sumState(traffic_out) AS traffic_out_state,
       sumState(traffic_in) AS traffic_in_state
FROM (
    SELECT
       timescale,
       dvid,
       _adomoid,
       vpnusergroup,
       xauthuser,
       user,
       vpnname,
       remip,
       locip,
       tunneltype,
       tunnelid,
       vpntunnel,
       vpntype,
       minMerge(s_time_state) AS s_time,
       maxMerge(e_time_state) AS e_time,
       maxMerge(max_duration_state) AS max_duration,
       minMerge(min_duration_state) AS min_duration,
       sumMerge(traffic_out_state) AS traffic_out,
       sumMerge(traffic_in_state) AS traffic_in
    FROM siem.fv_ffw_e_ipsec_hour_sp$SPID
    GROUP BY _adomoid, dvid, timescale, vpnusergroup, xauthuser,
        user, vpnname,  remip, locip, tunneltype, tunnelid, vpntunnel, vpntype
)
GROUP BY _adomoid, dvid, timescale, vpnusergroup, xauthuser,
    user, vpnname,  remip, locip, tunneltype, tunnelid, vpntunnel, vpntype;

ALTER TABLE siem.fv_ffw_e_ipsec_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
