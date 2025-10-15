/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_ffw_t_src_dst",
    "datasource_mv": "fv_ffw_t_src_dst_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_ffw_t_src_dst_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_ffw_t_src_dst_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_ffw_t_src_dst_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_ffw_t_src_dst_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_ffw_t_src_dst_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_ffw_t_src_dst_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_ffw_t_src_dst_5min_sp$SPID (
    timescale DateTime, dvid Int32, f_user Nullable(String), f_group Nullable(String),
    _adomoid UInt64,
    flags UInt32,
    d_flags UInt32,
    dstowner LowCardinality(Nullable(String)),
    dstcountry LowCardinality(Nullable(String)),
    dstintf LowCardinality(Nullable(String)),
    dstip Nullable(IPv6),
    dstuuid Nullable(UUID),
    srcintfrole LowCardinality(Nullable(String)), dstintfrole LowCardinality(Nullable(String)),
    epid Nullable(Int32), srcip Nullable(IPv6), srcintf LowCardinality(Nullable(String)),
    srcuuid Nullable(UUID),
    srcmac_state AggregateFunction(max, Nullable(String)),
    dev_src Nullable(String),
    dstmac_state AggregateFunction(max, Nullable(String)), devtype Nullable(String),
    app_group Nullable(String), domain Nullable(String), hostname Nullable(String),
    catdesc LowCardinality(Nullable(String)), policymode LowCardinality(Nullable(String)), policyid Nullable(UInt32),
	policytype LowCardinality(Nullable(String)), poluuid Nullable(UUID), policyname Nullable(String),
    avatar_state  AggregateFunction(max, Nullable(String)),
    epeuid_state  AggregateFunction(max, Nullable(String)),
    logtime_state AggregateFunction(max, DateTime), threatlvl_state AggregateFunction(max, Int8),
    threatweight_state AggregateFunction(sum, Int64), threatblock_state AggregateFunction(sum, Int64),
    thwgt_cri_state AggregateFunction(sum, Int64), thwgt_hig_state AggregateFunction(sum, Int64),
    thwgt_med_state AggregateFunction(sum, Int64), thwgt_low_state AggregateFunction(sum, Int64),
    bandwidth_state AggregateFunction(sum, Int64), traffic_in_state AggregateFunction(sum, Int64),
    traffic_out_state AggregateFunction(sum, Int64), session_block_state AggregateFunction(sum, Int64),
    incident_block_state AggregateFunction(sum, Int64),
    incident_state AggregateFunction(sum, Int64),
    browse_time_state AggregateFunction(browseTime, UInt64),
    sessions_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, srcintfrole, dstintfrole)
ORDER BY (_adomoid, dvid, timescale, srcintfrole, dstintfrole, srcip, devtype, dev_src, dstip, dstuuid,
         epid, f_user, f_group, srcintf, srcuuid, dstintf, dstowner, dstcountry,
         app_group, flags,
         catdesc, policymode, policyid, policytype, poluuid, policyname,
         domain, hostname)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;


CREATE TABLE IF NOT EXISTS siem.fv_ffw_t_src_dst_hour_sp$SPID AS siem.fv_ffw_t_src_dst_5min_sp$SPID;


CREATE TABLE IF NOT EXISTS siem.fv_ffw_t_src_dst_day_sp$SPID AS siem.fv_ffw_t_src_dst_5min_sp$SPID;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_ffw_t_src_dst_5min_mv_sp$SPID
TO siem.fv_ffw_t_src_dst_5min_sp$SPID
AS SELECT _adomoid, dvid, srcintfrole, dstintfrole, 
       fv_timescale_func(itime, 300, 0) AS timescale,
       coalesce(nullifna(user), nullifna(unauthuser)) AS f_user,
       `group` AS f_group, srcip, srcintf, srcuuid, maxState(srcmac) AS srcmac_state,
       dev_src, dstip, dstuuid, dstintf, dstowner, dstcountry,
       maxState(dstmac) AS dstmac_state,
       devtype, flags, d_flags, 
       app_group, domain, hostname, catdesc, policymode, policyid, policytype, poluuid, policyname,
       maxState(avatar) AS avatar_state,
       maxState(epeuid) AS epeuid_state, maxState(dtime) AS logtime_state,
       maxState(threatlvl) AS threatlvl_state, sumState(threatwgt) AS threatweight_state,
       sumState(threat_block) AS threatblock_state,
       sumState(thwgt_cri) AS thwgt_cri_state, sumState(thwgt_hig) AS thwgt_hig_state,
       sumState(thwgt_med) AS thwgt_med_state, sumState(thwgt_low) AS thwgt_low_state,
       sumState(toInt64(bandwidth)) AS bandwidth_state, sumState(toInt64(traffic_in)) AS traffic_in_state,
       sumState(toInt64(traffic_out)) AS traffic_out_state, sumState(toInt64(session_block)) AS session_block_state,
       browseTimeStateArray(ebtime) AS browse_time_state,
       sumState(toInt64(session_block)) AS incident_block_state,
       sumState(toInt64(sessions)) AS incident_state,
       sumState(toInt64(sessions)) AS sessions_state
    FROM (
       SELECT
           itime,
           dvid,
           (case when epid<1024 then NULL else epid end) as epid,
           _adomoid,
           _devlogtype,
           $LOGFIELD-srcintfrole,
           $LOGFIELD-dstintfrole, 
           $LOGFIELD-user, 
           $LOGFIELD-unauthuser,
           $LOGFIELD-group,
           $LOGFIELD-srcip,
           $LOGFIELD-srcintf,
           $LOGFIELD-srcuuid,
           $LOGFIELD-srcmac,
           $LOGFIELD-srcname,
           coalesce(srcname, srcmac) AS dev_src,
           $LOGFIELD-dstip,
           $LOGFIELD-dstuuid,
           $LOGFIELD-dstintf,
           $LOGFIELD-dstowner,
           $LOGFIELD-dstmac,
           $LOGFIELD-srcswversion,
           $LOGFIELD-osname,
           $LOGFIELD-devtype-t_devtype, get_devtype(srcswversion, osname, t_devtype) devtype,
           $LOGFIELD-dstcountry,
           $LOGFIELD-app, 
           $LOGFIELD-vwlname,
           $LOGFIELD-vwlservice,
           $LOGFIELD-catdesc,
           $LOGFIELD-policymode,
           $LOGFIELD-policyid,
           $LOGFIELD-policytype, 
           $LOGFIELD-poluuid, 
           $LOGFIELD-policyname,
           app_group_name(app) AS app_group,
           $LOGFIELD-hostname, 
           logflag, 
           $LOGFIELD-unauthuser,
           root_domain(hostname) AS domain, hostname, 
           $LOGFIELD-appcat,
           multiIf(appcat='unscanned',1,0) AS flags,
           (CASE WHEN appcat='unscanned' THEN 1 ELSE 0 END) AS d_flags, 
           (CASE WHEN $LOGFIELD_NOALIAS-fctuid IS NOT NULL AND unauthuser IS NOT NULL THEN CONCAT(toString($LOGFIELD_NOALIAS-fctuid), ',', unauthuser) ELSE NULL END) AS avatar,
           ( CASE WHEN epid > 1023 AND euid != 0 THEN CONCAT(toString(epid), ',', toString(euid)) ELSE NULL END) AS epeuid,
           $LOGFIELD-ebtime,
           dtime,
           $LOGFIELD-threatlvls,
           $LOGFIELD-threatwgts,
           $LOGFIELD-threatcnts,
           threatlevel_max(threatlvls) AS threatlvl,
           threatweight_sum(threatwgts, threatcnts) AS threatwgt,
           ( CASE WHEN(bitAnd(logflag, 2) > 0) THEN threatwgt ELSE 0 END) AS threat_block, 
           threatweight_level_sum(4,threatlvls,threatcnts,threatwgts) AS thwgt_cri,
           threatweight_level_sum(3,threatlvls,threatcnts,threatwgts) AS thwgt_hig,
           threatweight_level_sum(2,threatlvls,threatcnts,threatwgts) AS thwgt_med,
           threatweight_level_sum(1,threatlvls,threatcnts,threatwgts) AS thwgt_low,
           $LOGFIELD-sentbyte,
           $LOGFIELD-rcvdbyte, 
           $LOGFIELD-sentdelta,
           $LOGFIELD-rcvddelta,
           coalesce(sentdelta, sentbyte, 0)+coalesce(rcvddelta, rcvdbyte, 0) AS bandwidth,
           coalesce(rcvddelta, rcvdbyte, 0) AS traffic_in,
           coalesce(sentdelta, sentbyte, 0) AS traffic_out,
           CAST(( CASE WHEN(bitAnd(logflag, 2) > 0) THEN 1 ELSE 0 END), 'Int64') AS session_block, 
           1 AS sessions
      FROM siem.tlog_sp$SPID
      WHERE _devlogtype = 21010
)
GROUP BY _adomoid, dvid, srcintfrole, dstintfrole, timescale,
     epid, f_user, f_group, srcip, srcintf, srcuuid, devtype, dev_src, dstip, dstuuid, dstintf, dstowner, dstcountry,
     app_group, flags, d_flags,
     catdesc, policymode, policyid, policytype, poluuid, policyname,
     domain, hostname;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_ffw_t_src_dst_hour_mv_sp$SPID
TO siem.fv_ffw_t_src_dst_hour_sp$SPID
AS SELECT dvid, srcintfrole, dstintfrole,
       fv_timescale_func(timescale, 3600, 0) AS timescale,
       _adomoid, flags, d_flags,
       f_user, dstowner, dstcountry, dstintf, dstip, dstuuid,
       f_group, srcip, srcintf, srcuuid, maxState(srcmac) AS srcmac_state,
       dev_src,
       maxState(dstmac) AS dstmac_state,
       devtype,
       app_group, domain, hostname, catdesc, policymode, policyid, policytype, poluuid, policyname,
       maxState(avatar) AS avatar_state,
       maxState(epeuid) AS epeuid_state, maxState(logtime) AS logtime_state,
       maxState(threatlvl) AS threatlvl_state, sumState(threatwgt) AS threatweight_state,
       sumState(threat_block) AS threatblock_state,
       sumState(thwgt_cri) AS thwgt_cri_state, sumState(thwgt_hig) AS thwgt_hig_state,
       sumState(thwgt_med) AS thwgt_med_state, sumState(thwgt_low) AS thwgt_low_state,
       sumState(bandwidth) AS bandwidth_state, sumState(traffic_in) AS traffic_in_state,
       sumState(traffic_out) AS traffic_out_state, sumState(session_block) AS session_block_state,
       browseTimeMergeState(b2) AS browse_time_state,
       sumState(incidents) AS incident_state,
       sumState(incident_block) AS incident_block_state,
       sumState(sessions) AS sessions_state
FROM (
    SELECT
        timescale, epid, f_user, f_group, srcip, srcintf, srcuuid,
        _adomoid, flags, d_flags,
        dstip, dstuuid, dstintf, dstowner, dstcountry,
        app_group, domain, hostname, catdesc, policymode, policyid, policytype, poluuid, policyname,
        dstintfrole, dvid, srcintfrole,
        maxMerge(srcmac_state) AS srcmac,
        dev_src,
        maxMerge(dstmac_state) AS dstmac,
        devtype,
        maxMerge(avatar_state) AS avatar,
        maxMerge(epeuid_state) AS epeuid,
        maxMerge(logtime_state) AS logtime,
        maxMerge(threatlvl_state) AS threatlvl,
        sumMerge(threatweight_state) AS threatwgt,
        sumMerge(threatblock_state) AS threat_block,
        sumMerge(thwgt_cri_state) AS thwgt_cri,
        sumMerge(thwgt_hig_state) AS thwgt_hig,
        sumMerge(thwgt_med_state) AS thwgt_med,
        sumMerge(thwgt_low_state) AS thwgt_low,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(traffic_out_state) AS traffic_out,
        sumMerge(session_block_state) AS session_block,
        sumMerge(incident_block_state) AS incident_block,
        sumMerge(incident_state) AS incidents,
        browseTimeMergeState(browse_time_state) AS b2,
        sumMerge(sessions_state) AS sessions
    FROM siem.fv_ffw_t_src_dst_5min_sp$SPID
    GROUP BY _adomoid, dvid, srcintfrole, dstintfrole, timescale,
         epid, f_user, f_group, srcip, srcintf, srcuuid, devtype, dev_src, dstip, dstuuid, dstintf, dstowner, dstcountry,
         app_group, flags, d_flags,
         catdesc, policymode, policyid, policytype, poluuid, policyname, 
         domain, hostname
)
GROUP BY _adomoid, dvid, srcintfrole, dstintfrole, timescale,
     epid, f_user, f_group, srcip, srcintf, srcuuid, devtype, dev_src, dstip, dstuuid, dstintf, dstowner, dstcountry,
     app_group, flags, d_flags,
     catdesc, policymode, policyid, policytype, poluuid, policyname,
     domain, hostname;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_ffw_t_src_dst_day_mv_sp$SPID
TO siem.fv_ffw_t_src_dst_day_sp$SPID
AS SELECT _adomoid, dvid, srcintfrole, dstintfrole,
       fv_timescale_func(timescale, 28800, 0) AS timescale,
       f_user, dstowner, dstcountry, dstintf, dstip, dstuuid, flags, d_flags,
       f_group, srcip, srcintf, srcuuid, maxState(srcmac) AS srcmac_state,
       dev_src,
       maxState(dstmac) AS dstmac_state, devtype,
       app_group, domain, hostname, catdesc, policymode, policyid, policytype, poluuid, policyname,
       maxState(avatar) AS avatar_state,
       maxState(epeuid) AS epeuid_state, maxState(logtime) AS logtime_state,
       maxState(threatlvl) AS threatlvl_state, sumState(threatwgt) AS threatweight_state,
       sumState(threat_block) AS threatblock_state,
       sumState(thwgt_cri) AS thwgt_cri_state, sumState(thwgt_hig) AS thwgt_hig_state,
       sumState(thwgt_med) AS thwgt_med_state, sumState(thwgt_low) AS thwgt_low_state,
       sumState(bandwidth) AS bandwidth_state, sumState(traffic_in) AS traffic_in_state,
       sumState(traffic_out) AS traffic_out_state, sumState(session_block) AS session_block_state,
       browseTimeMergeState(_browse_time) AS browse_time_state,
       sumState(incidents) AS incident_state,
       sumState(incident_block) AS incident_block_state,
       sumState(sessions) AS sessions_state
FROM (
    SELECT
        timescale, epid, f_user, f_group, srcip, srcintf, srcuuid,
        _adomoid, flags, d_flags,
        dstip, dstuuid, dstintf, dstowner, dstcountry,
        app_group, domain, hostname, catdesc, policymode, policyid, policytype, poluuid, policyname,
        dstintfrole, dvid, srcintfrole,
        maxMerge(srcmac_state) AS srcmac,
        dev_src,
        maxMerge(dstmac_state) AS dstmac,
        devtype,
        maxMerge(avatar_state) AS avatar,
        maxMerge(epeuid_state) AS epeuid,
        maxMerge(logtime_state) AS logtime,
        maxMerge(threatlvl_state) AS threatlvl,
        sumMerge(threatweight_state) AS threatwgt,
        sumMerge(threatblock_state) AS threat_block,
        sumMerge(thwgt_cri_state) AS thwgt_cri,
        sumMerge(thwgt_hig_state) AS thwgt_hig,
        sumMerge(thwgt_med_state) AS thwgt_med,
        sumMerge(thwgt_low_state) AS thwgt_low,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(traffic_out_state) AS traffic_out,
        sumMerge(session_block_state) AS session_block,
        browseTimeMergeState(browse_time_state) AS _browse_time,
        sumMerge(incident_state) AS incidents,
        sumMerge(incident_block_state) AS incident_block,
        sumMerge(sessions_state) AS sessions
    FROM siem.fv_ffw_t_src_dst_hour_sp$SPID
    GROUP BY _adomoid, dvid, srcintfrole, dstintfrole, timescale,
         epid, f_user, f_group, srcip, srcintf, srcuuid, devtype, dev_src, dstip, dstuuid, dstintf, dstowner, dstcountry,
         app_group, flags, d_flags,
         catdesc, policymode, policyid, policytype, poluuid, policyname,
         domain, hostname
)
GROUP BY _adomoid, dvid, srcintfrole, dstintfrole, timescale,
     epid, f_user, f_group, srcip, srcintf, srcuuid, devtype, dev_src, dstip, dstuuid, dstintf, dstowner, dstcountry,
     app_group, flags,d_flags,
     catdesc, policymode, policyid, policytype, poluuid, policyname,
     domain, hostname;

ALTER TABLE siem.fv_ffw_t_src_dst_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
