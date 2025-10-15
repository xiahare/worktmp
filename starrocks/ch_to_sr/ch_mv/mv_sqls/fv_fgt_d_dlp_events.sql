/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_d_dlp_events",
    "datasource_mv": "fv_fgt_d_dlp_events_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_d_dlp_events_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_d_dlp_events_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_d_dlp_events_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_d_dlp_events_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_d_dlp_events_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_d_dlp_events_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_d_dlp_events_5min_sp$SPID (
    timescale DateTime,
    _adomoid UInt64,
    dvid Int32,
    application Nullable(String),
    severity LowCardinality(Nullable(String)),
    filename Nullable(String),
    sensitivity LowCardinality(Nullable(String)),
    action_type LowCardinality(Nullable(String)),
    traffic_direction LowCardinality(Nullable(String)),
    f_user Nullable(String),
    srcip Nullable(IPv6),
    dstcountry Nullable(String),
    service LowCardinality(Nullable(String)),
    profile Nullable(String),
    policyid Nullable(UInt32),
    policytype LowCardinality(Nullable(String)),
    dstintf LowCardinality(Nullable(String)),
    srcintf LowCardinality(Nullable(String)),
    user_src Nullable(String),
    filesize_state AggregateFunction(sum, Nullable(Int64)),
    sessions_state AggregateFunction(sum, Int64),
    session_block_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, application, severity, filename)
ORDER BY (_adomoid, dvid, timescale, application, severity, filename, sensitivity,
        action_type, traffic_direction)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;



CREATE TABLE IF NOT EXISTS siem.fv_fgt_d_dlp_events_hour_sp$SPID AS siem.fv_fgt_d_dlp_events_5min_sp$SPID;


CREATE TABLE IF NOT EXISTS siem.fv_fgt_d_dlp_events_day_sp$SPID AS siem.fv_fgt_d_dlp_events_5min_sp$SPID;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_d_dlp_events_5min_mv_sp$SPID
TO siem.fv_fgt_d_dlp_events_5min_sp$SPID
AS SELECT 
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    application,
    severity,
    filename,
    sensitivity,
    action_type,
    traffic_direction,
    f_user,
    srcip,
    dstcountry,
    service,
    profile,
    policyid,
    policytype,
    dstintf,
    srcintf,
    user_src,
    sumState(toInt64(filesize)) AS filesize_state,
    sumState(toInt64(sessions)) AS sessions_state,
    sumState(toInt64(session_block)) AS session_block_state
FROM (
      SELECT
        _adomoid,
        dvid,
        itime AS timescale,
        $LOGFIELD-hostname,
        $LOGFIELD-severity,
        $LOGFIELD-filename,
        $LOGFIELD-action,
        $LOGFIELD-direction, 
        $LOGFIELD-user,
        $LOGFIELD-unauthuser,
        $LOGFIELD-srcip,
        $LOGFIELD-dstcountry,
        $LOGFIELD-service,
        $LOGFIELD-profile,
        $LOGFIELD-filesize,
        hostname AS application,
        $LOGFIELD-policyid,
        $LOGFIELD-policytype,
        $LOGFIELD-dstintf,
        $LOGFIELD-srcintf,
        coalesce(nullifna(`user`), nullifna(`unauthuser`), ipstr(`srcip`)) AS user_src, 
        coalesce($LOGFIELD_NOALIAS-sensitivity, 'Unclassified') AS sensitivity,
        (CASE WHEN action = 'block' THEN 'Block' ELSE 'Allow' END) AS action_type, 
        (CASE WHEN direction='incoming' THEN 'Download' ELSE 'Upload' END) AS traffic_direction, 
        coalesce(nullifna("user"), nullifna("unauthuser")) AS f_user,
        (CASE WHEN action = 'block' THEN 1 ELSE 0 END) AS session_block,
        1 AS sessions
      FROM siem.ulog_sp$SPID
      WHERE hostname IS NOT NULL  AND action IN ('log-only', 'exempt','block')
            AND _devlogtype = 3
)
GROUP BY _adomoid, dvid, timescale, application, severity, filename, sensitivity,
        action_type, traffic_direction, f_user, srcip, dstcountry,
        service, profile, policyid, policytype, dstintf, srcintf, user_src;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_d_dlp_events_hour_mv_sp$SPID
TO siem.fv_fgt_d_dlp_events_hour_sp$SPID
AS SELECT 
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    application,
    severity,
    filename,
    sensitivity,
    action_type,
    traffic_direction,
    f_user,
    srcip,
    dstcountry,
    service,
    profile,
    policyid,
    policytype,
    dstintf,
    srcintf,
    user_src,
    sumState(filesize) AS filesize_state,
    sumState(sessions) AS sessions_state,
    sumState(session_block) AS session_block_state
FROM (
      SELECT
        _adomoid,
        dvid,
        timescale,
        application,
        severity,
        filename,
        sensitivity,
        action_type,
        traffic_direction,
        f_user,
        srcip,
        dstcountry,
        service,
        profile,
        policyid,
        policytype,
        dstintf,
        srcintf,
        user_src,
        sumMerge(filesize_state) AS filesize,
        sumMerge(sessions_state) AS sessions,
        sumMerge(session_block_state) AS session_block
      FROM siem.fv_fgt_d_dlp_events_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale, application, severity, filename, sensitivity,
               action_type, traffic_direction, f_user, srcip, dstcountry, service, profile,
               policyid, policytype, dstintf, srcintf, user_src
)
GROUP BY _adomoid, dvid, timescale, application, severity, filename, sensitivity,
         action_type, traffic_direction, f_user, srcip, dstcountry,
         service, profile, policyid, policytype, dstintf, srcintf, user_src;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_d_dlp_events_day_mv_sp$SPID
TO siem.fv_fgt_d_dlp_events_day_sp$SPID
AS SELECT 
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    application,
    severity,
    filename,
    sensitivity,
    action_type,
    traffic_direction,
    f_user,
    srcip,
    dstcountry,
    service,
    profile,
    policyid,
    policytype,
    dstintf,
    srcintf,
    user_src,
    sumState(filesize) AS filesize_state,
    sumState(sessions) AS sessions_state,
    sumState(session_block) AS session_block_state
FROM (
      SELECT
        _adomoid,
        dvid,
        timescale,
        application,
        severity,
        filename,
        sensitivity,
        action_type,
        traffic_direction,
        f_user,
        srcip,
        dstcountry,
        service,
        profile,
        policyid,
        policytype,
        dstintf,
        srcintf,
        user_src,
        sumMerge(filesize_state) AS filesize,
        sumMerge(sessions_state) AS sessions,
        sumMerge(session_block_state) AS session_block
      FROM siem.fv_fgt_d_dlp_events_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale, application, severity, filename, sensitivity,
               action_type, traffic_direction, f_user, srcip, dstcountry, service, profile,
               policyid, policytype, dstintf, srcintf, user_src
)
GROUP BY _adomoid, dvid, timescale, application, severity, filename, sensitivity,
         action_type, traffic_direction, f_user, srcip, dstcountry,
         service, profile, policyid, policytype, dstintf, srcintf, user_src;

ALTER TABLE siem.fv_fgt_d_dlp_events_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
