/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_v_fsa_detection",
    "datasource_mv": "fv_fgt_v_fsa_detection_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_detection_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_detection_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_detection_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_detection_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_detection_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_detection_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_v_fsa_detection_5min_sp$SPID (
    timescale DateTime, dvid Int32, _adomoid UInt64,
    analyticscksum Nullable(String),
    user_src Nullable(String),
    action Nullable(String),
    srcip Nullable(IPv6),
    dstip Nullable(IPv6),
    srcintf LowCardinality(Nullable(String)),
    dstintf LowCardinality(Nullable(String)),
    policyid Nullable(UInt32),
    policytype LowCardinality(Nullable(String)),
    itime DateTime,
    sessionid Nullable(UInt32),
    doc_name Nullable(String),
    avatar Nullable(String),
    epeuid Nullable(String),
    service LowCardinality(Nullable(String)),
    verdict_level Int32
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, timescale, dvid, itime)
ORDER BY (_adomoid, timescale, dvid, itime)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_v_fsa_detection_hour_sp$SPID AS siem.fv_fgt_v_fsa_detection_5min_sp$SPID;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_v_fsa_detection_day_sp$SPID AS siem.fv_fgt_v_fsa_detection_5min_sp$SPID;
CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_v_fsa_detection_5min_mv_sp$SPID
TO siem.fv_fgt_v_fsa_detection_5min_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    analyticscksum, user_src, action, 
    srcip, dstip,
    srcintf, dstintf, policyid, policytype,
    itime,
    sessionid,
    doc_name,
    avatar, epeuid,
    service,
    verdict_level
    FROM (
       SELECT DISTINCT ON (_adomoid, dvid, timescale, analyticscksum, user_src)
           _adomoid, dvid, timescale, analyticscksum, user_src, action,
           srcip, dstip,
           srcintf, dstintf, policyid, policytype,
           itime,
           sessionid,
           (CASE WHEN user_src IS NOT NULL THEN coalesce(filename, url) ELSE NULL END) AS doc_name,
           avatar, epeuid,
           service,
           verdict_level
       FROM (
           SELECT _adomoid, dvid, fv_timescale_func(itime, 3600, 0) AS timescale,
                  ucase($LOGFIELD_NOALIAS-analyticscksum) AS analyticscksum,
                  itime,
                  $LOGFIELD-sessionid,
                  $LOGFIELD-action-_action,
                  $LOGFIELD-user,
                  $LOGFIELD-eventtype,
                  $LOGFIELD-dtype,
                  $LOGFIELD-service,
                  $LOGFIELD-filename,
                  $LOGFIELD-url,
                  (CASE WHEN dtype IS NULL and eventtype = 'analytics' THEN coalesce(nullifna(`user`), nullifna(`unauthuser`), ipstr(`srcip`)) ELSE NULL END) AS user_src,
                  (CASE WHEN eventtype != 'analytics' AND _action= 'blocked' THEN 'blocked' ELSE 'passthrough' END) AS action,
                  $LOGFIELD-srcip,
                  $LOGFIELD-dstip,
                  $LOGFIELD-fctuid,
                  $LOGFIELD-unauthuser,
                  $LOGFIELD-srcintf,
                  $LOGFIELD-dstintf,
                  $LOGFIELD-policyid,
                  $LOGFIELD-policytype,
                  (CASE WHEN fctuid IS NOT NULL AND unauthuser IS NOT NULL THEN CONCAT(toString(fctuid), ',', unauthuser) ELSE NULL END) AS avatar,
                  (CASE WHEN epid > 1023 AND euid != 0 THEN CONCAT(toString(epid), ',', toString(euid)) ELSE NULL END) AS epeuid,
                  $LOGFIELD-fsaverdict,
                  (CASE WHEN fsaverdict = 'malicious' THEN 3 WHEN fsaverdict IN ('high risk', 'medium risk', 'low risk') THEN 2
                    WHEN fsaverdict = 'clean' THEN 1 ELSE 0 END) AS verdict_level
            FROM siem.ulog_sp$SPID
            WHERE _devlogtype = 11 AND analyticscksum IS NOT NULL
        ) t
        ORDER BY _adomoid, dvid, timescale, analyticscksum, user_src, itime DESC
    );

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_v_fsa_detection_hour_mv_sp$SPID
TO siem.fv_fgt_v_fsa_detection_hour_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    analyticscksum, user_src, action,
    srcip, dstip,
    srcintf, dstintf, policyid, policytype,
    itime,
    sessionid,
    doc_name,
    avatar, epeuid,
    service,
    verdict_level
    FROM (
       SELECT DISTINCT ON (1, 2, 3, 4, 5)
           _adomoid, dvid, timescale, analyticscksum, user_src, action,
           srcip, dstip,
           srcintf, dstintf, policyid, policytype,
           itime,
           sessionid, doc_name,
           avatar, epeuid,
           service,
           verdict_level
       FROM siem.fv_fgt_v_fsa_detection_5min_sp$SPID
    ) t
    ORDER BY 1, 2, 3, 4, 5, itime DESC;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_v_fsa_detection_day_mv_sp$SPID
TO siem.fv_fgt_v_fsa_detection_day_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    analyticscksum, user_src, action,
    srcip, dstip,
    srcintf, dstintf, policyid, policytype,
    itime,
    sessionid,
    doc_name,
    avatar, epeuid,
    service,
    verdict_level
    FROM (
       SELECT DISTINCT ON (1, 2, 3, 4, 5)
           _adomoid, dvid, timescale, analyticscksum, user_src, action,
           srcip, dstip,
           srcintf, dstintf, policyid, policytype,
           itime,
           sessionid, doc_name,
           avatar, epeuid,
           service,
           verdict_level
       FROM siem.fv_fgt_v_fsa_detection_hour_sp$SPID
    ) t
    ORDER BY 1, 2, 3, 4, 5, itime DESC;

ALTER TABLE siem.fv_fgt_v_fsa_detection_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
