/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_t_src_dst_threat",
    "datasource_mv": "fv_fgt_t_src_dst_threat_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_t_src_dst_threat_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_src_dst_threat_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_src_dst_threat_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_src_dst_threat_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_src_dst_threat_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_src_dst_threat_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_src_dst_threat_5min_sp$SPID (
    timescale DateTime,
    _adomoid UInt64,
    dvid Int32,
    f_user Nullable(String),
    srcip Nullable(IPv6),
    srcintf LowCardinality(Nullable(String)),
    srcintfrole LowCardinality(Nullable(String)),
    dstip Nullable(IPv6),
    dstintf LowCardinality(Nullable(String)),
    dstintfrole LowCardinality(Nullable(String)),
    dstcountry LowCardinality(Nullable(String)),
    policyid Nullable(UInt32),
	policytype LowCardinality(Nullable(String)),
    devtype Nullable(String),
    dev_src Nullable(String),
    app_group Nullable(String),
    avatar_state  AggregateFunction(max, Nullable(String)),
    epeuid_state  AggregateFunction(max, Nullable(String)),
    threats Array(Nullable(String)),
    threattypes Array(Nullable(String)),
    threatlevels Array(Nullable(Int64)),
    threatweight_state AggregateFunction(sum, Nullable(Int64)),
    threatblock_state AggregateFunction(sum, Nullable(Int64)),
    bandwidth_state AggregateFunction(sum, Nullable(Int64)),
    traffic_in_state AggregateFunction(sum, Nullable(Int64)),
    traffic_out_state AggregateFunction(sum, Nullable(Int64)),
    session_block_state AggregateFunction(sum, Int64),
    sessions_state AggregateFunction(sum, Int64), 
    incident_block_state AggregateFunction(sum, Int64),
    incident_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, timescale, dvid, f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole)
ORDER BY (_adomoid, timescale, dvid,
          f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole, dstcountry, policyid, policytype,
          devtype, dev_src, app_group, threats, threattypes, threatlevels)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_src_dst_threat_hour_sp$SPID AS siem.fv_fgt_t_src_dst_threat_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_src_dst_threat_day_sp$SPID AS siem.fv_fgt_t_src_dst_threat_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_src_dst_threat_5min_mv_sp$SPID
TO siem.fv_fgt_t_src_dst_threat_5min_sp$SPID
AS SELECT _adomoid, dvid,
    fv_timescale_func(itime, 300, 0) AS timescale,
    f_user,
    srcip,
    srcintf,
    srcintfrole,
    dstip,
    dstintf,
    dstintfrole,
    dstcountry,
    policyid,
    policytype,
    devtype,
    dev_src,
    app_group,
    maxState(avatar) AS avatar_state,
    maxState(epeuid) AS epeuid_state,
    threats,
    threattypes,
    threatlevels,
    sumState(toInt64(threatweight)) AS threatweight_state,
    sumState(toInt64(threat_block)) AS threatblock_state,
    sumState(toInt64(bandwidth)) AS bandwidth_state,
    sumState(toInt64(traffic_in)) AS traffic_in_state,
    sumState(toInt64(traffic_out)) AS traffic_out_state,
    sumState(session_block) AS session_block_state,
    sumState(sessions) AS sessions_state,
    sumState(toInt64(incident_block)) AS incident_block_state,
    sumState(toInt64(incidents)) AS incident_state 
    FROM (
       SELECT
           itime,
           dvid,
           _adomoid,
           _devlogtype,
           $LOGFIELD-unauthuser,
           $LOGFIELD-user,
           coalesce(nullifna(`user`), nullifna(`unauthuser`)) AS f_user,
           $LOGFIELD-srcip,
           $LOGFIELD-srcintf,
           $LOGFIELD-srcintfrole,
           $LOGFIELD-dstip,
           $LOGFIELD-dstintf,
           $LOGFIELD-dstintfrole,
           $LOGFIELD-dstcountry,
           $LOGFIELD-policyid,
           $LOGFIELD-policytype,
           $LOGFIELD-devtype,
           $LOGFIELD-srcname,
           $LOGFIELD-srcmac,
           $LOGFIELD-app,
           coalesce_str(srcname, srcmac) AS dev_src,
           app_group_name(app) AS app_group,
           $LOGFIELD-fctuid,
           $LOGFIELD-unauthuser,
           (CASE WHEN fctuid IS NOT NULL AND unauthuser IS NOT NULL THEN CONCAT(toString(fctuid), ',', unauthuser) ELSE NULL END) AS avatar,
           ( CASE WHEN epid > 1023 AND euid IS NOT NULL THEN CONCAT(toString(epid), ',', toString(euid)) ELSE NULL END) AS epeuid,
           $LOGFIELD-threats,
           $LOGFIELD-threattyps-threattypes,
           $LOGFIELD-threatlvls-threatlevels,
           $LOGFIELD-crscore,
           bitAnd(crscore, 65535) AS threatweight,
           (CASE WHEN (bitAnd(logflag, 2) >0) THEN bitAnd(crscore, 65535) ELSE 0 END) AS threat_block,
           $LOGFIELD-sentbyte,
           $LOGFIELD-rcvdbyte,
           sentbyte + rcvdbyte AS bandwidth,
           rcvdbyte AS traffic_in,
           sentbyte AS traffic_out,
           CAST(( CASE WHEN(bitAnd(logflag, 2) > 0) THEN 1 ELSE 0 END), 'Int64') AS session_block,
           CAST(( CASE WHEN(bitAnd(logflag, 1) > 0) THEN 1 ELSE 0 END), 'Int64') AS sessions,
           (CASE WHEN (bitAnd(logflag,2)>0) THEN 1 ELSE 0 END) AS incident_block,
           1 AS incidents 
      FROM siem.tlog_sp$SPID
      WHERE _devlogtype = 10 AND threats IS NOT NULL
)
GROUP BY _adomoid, dvid, timescale,
         f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole, dstcountry, policyid, policytype,
         devtype, dev_src, app_group, threats, threattypes, threatlevels;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_src_dst_threat_hour_mv_sp$SPID
TO siem.fv_fgt_t_src_dst_threat_hour_sp$SPID
AS SELECT _adomoid, dvid,
        fv_timescale_func(timescale, 3600, 0) AS timescale,
        f_user,
        srcip,
        srcintf,
        srcintfrole,
        dstip,
        dstintf,
        dstintfrole,
        dstcountry,
        policyid,
        policytype,
        devtype,
        dev_src,
        app_group,
        maxState(avatar) AS avatar_state,
        maxState(epeuid) AS epeuid_state,
        threats,
        threattypes,
        threatlevels,
        sumState(threatweight) AS threatweight_state,
        sumState(threat_block) AS threatblock_state,
        sumState(bandwidth) AS bandwidth_state,
        sumState(traffic_in) AS traffic_in_state,
        sumState(traffic_out) AS traffic_out_state,
        sumState(session_block) AS session_block_state,
        sumState(sessions) AS sessions_state,
        sumState(incident_block) AS incident_block_state,
        sumState(incidents) AS incident_state
FROM (
   SELECT _adomoid, dvid,
        timescale,
        f_user,
        srcip,
        srcintf,
        srcintfrole,
        dstip,
        dstintf,
        dstintfrole,
        dstcountry,
        policyid,
        policytype,
        devtype,
        dev_src,
        app_group,
        maxMerge(avatar_state) AS avatar,
        maxMerge(epeuid_state) AS epeuid,
        threats,
        threattypes,
        threatlevels,
        sumMerge(threatweight_state) AS threatweight,
        sumMerge(threatblock_state) AS threat_block,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(traffic_out_state) AS traffic_out,
        sumMerge(session_block_state) AS session_block,
        sumMerge(sessions_state) AS sessions,
        sumMerge(incident_block_state) AS incident_block,
        sumMerge(incident_state) AS incidents
    FROM siem.fv_fgt_t_src_dst_threat_5min_sp$SPID
    GROUP BY _adomoid, dvid, timescale,
         f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole, dstcountry, policyid, policytype,
         devtype, dev_src, app_group, threats, threattypes, threatlevels
)
GROUP BY _adomoid, dvid, timescale,
         f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole, dstcountry, policyid, policytype,
         devtype, dev_src, app_group, threats, threattypes, threatlevels;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_src_dst_threat_day_mv_sp$SPID
TO siem.fv_fgt_t_src_dst_threat_day_sp$SPID
AS SELECT _adomoid, dvid,
        fv_timescale_func(timescale, 28800, 0) AS timescale,
        f_user,
        srcip,
        srcintf,
        srcintfrole,
        dstip,
        dstintf,
        dstintfrole,
        dstcountry,
        policyid,
        policytype,
        devtype,
        dev_src,
        app_group,
        maxState(avatar) AS avatar_state,
        maxState(epeuid) AS epeuid_state,
        threats,
        threattypes,
        threatlevels,
        sumState(threatweight) AS threatweight_state,
        sumState(threat_block) AS threatblock_state,
        sumState(bandwidth) AS bandwidth_state,
        sumState(traffic_in) AS traffic_in_state,
        sumState(traffic_out) AS traffic_out_state,
        sumState(session_block) AS session_block_state,
        sumState(sessions) AS sessions_state,
        sumState(incident_block) AS incident_block_state,
        sumState(incidents) AS incident_state
FROM (
   SELECT _adomoid, dvid,
        timescale,
        f_user,
        srcip,
        srcintf,
        srcintfrole,
        dstip,
        dstintf,
        dstintfrole,
        dstcountry,
        policyid,
        policytype,
        devtype,
        dev_src,
        app_group,
        maxMerge(avatar_state) AS avatar,
        maxMerge(epeuid_state) AS epeuid,
        threats,
        threattypes,
        threatlevels,
        sumMerge(threatweight_state) AS threatweight,
        sumMerge(threatblock_state) AS threat_block,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(traffic_out_state) AS traffic_out,
        sumMerge(session_block_state) AS session_block,
        sumMerge(sessions_state) AS sessions,
        sumMerge(incident_block_state) AS incident_block,
        sumMerge(incident_state) AS incidents
    FROM siem.fv_fgt_t_src_dst_threat_hour_sp$SPID
    GROUP BY _adomoid, dvid, timescale,
         f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole, dstcountry, policyid, policytype,
         devtype, dev_src, app_group, threats, threattypes, threatlevels
)
GROUP BY _adomoid, dvid, timescale,
         f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole, dstcountry, policyid, policytype,
         devtype, dev_src, app_group, threats, threattypes, threatlevels;

ALTER TABLE siem.fv_fgt_t_src_dst_threat_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
