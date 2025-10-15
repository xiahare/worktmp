/*
{
    "type": "sp_mv",
    "version": "070603.3445",
    "name": "fv_fgt_w_web_search",
    "datasource_mv": "fv_fgt_w_web_search_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_w_web_search_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_w_web_search_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_w_web_search_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_w_web_search_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_w_web_search_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_w_web_search_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_w_web_search_5min_sp$SPID (
    dvid Int32, srcintfrole LowCardinality(Nullable(String)),
    dstintfrole LowCardinality(Nullable(String)),
    timescale DateTime, _adomoid UInt64,
    keyword Nullable(String),
    hostname Nullable(String),
    f_user Nullable(String),
    userfield Nullable(String),
    srcip Nullable(IPv6),
    dstip Nullable(IPv6),
    policyid Nullable(UInt32),
    policytype LowCardinality(Nullable(String)),
    srcuuid Nullable(UUID),
    dstuuid Nullable(UUID),
    avatar_state AggregateFunction(max, Nullable(String)),
    epeuid_state AggregateFunction(max,Nullable(String)),
    search_count_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, timescale, dvid, srcintfrole, srcip, dstip, dstintfrole)
ORDER BY (_adomoid, timescale, dvid, srcintfrole, srcip, dstip, dstintfrole,
          policyid, policytype, keyword, hostname, f_user, userfield, srcuuid, dstuuid)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_w_web_search_hour_sp$SPID AS siem.fv_fgt_w_web_search_5min_sp$SPID;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_w_web_search_day_sp$SPID AS siem.fv_fgt_w_web_search_5min_sp$SPID;
CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_w_web_search_5min_mv_sp$SPID
TO siem.fv_fgt_w_web_search_5min_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    srcintfrole,
    dstintfrole,
    policyid,
    policytype,
    keyword,
    hostname,
    f_user,
    userfield,
    srcip,
    dstip,
    srcuuid,
    dstuuid,
    maxState(avatar) AS avatar_state,
    maxState(epeuid) AS epeuid_state,
    sumState(toInt64(search_count)) AS search_count_state
    FROM (
       SELECT
        _adomoid, dvid,
        itime AS timescale,
        $LOGFIELD-srcip,
        $LOGFIELD-dstip,
        $LOGFIELD-srcintfrole,
        $LOGFIELD-dstintfrole,
        $LOGFIELD-policyid,
        $LOGFIELD-policytype,
        $LOGFIELD-keyword,
        $LOGFIELD-hostname,
        coalesce(nullifna(`user`), nullifna(`unauthuser`)) AS f_user,
        $LOGFIELD-user,
        $LOGFIELD-unauthuser,
        (CASE WHEN nullifna(`user`) IS NOT NULL THEN 'user' ELSE 'unauthuser' END) AS userfield,
        $LOGFIELD-srcuuid,
        $LOGFIELD-dstuuid,
        $LOGFIELD-fctuid,
        (CASE WHEN fctuid IS NOT NULL AND unauthuser IS NOT NULL THEN CONCAT(toString(fctuid), ',', unauthuser) ELSE NULL END) AS avatar,
        (CASE WHEN epid > 1023 AND euid != 0 THEN CONCAT(toString(epid), ',', toString(euid)) ELSE NULL END) AS epeuid,
        1 AS search_count
      FROM siem.ulog_sp$SPID
      WHERE _devlogtype = 13 AND keyword IS NOT NULL
)
GROUP BY _adomoid, dvid, timescale,
         srcintfrole, srcip, dstip, dstintfrole, policyid, policytype,
         keyword, hostname, f_user, userfield, srcuuid, dstuuid;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_w_web_search_hour_mv_sp$SPID
TO siem.fv_fgt_w_web_search_hour_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    srcintfrole,
    dstintfrole,
    policyid,
    policytype,
    keyword,
    hostname,
    f_user,
    userfield,
    srcip,
    dstip,
    srcuuid,
    dstuuid,
    maxState(avatar) AS avatar_state,
    maxState(epeuid) AS epeuid_state,
    sumState(search_count) AS search_count_state
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        srcintfrole,
        dstintfrole,
        policyid,
        policytype,
        keyword,
        hostname,
        f_user,
        userfield,
        srcip,
        dstip,
        srcuuid,
        dstuuid,
        maxMerge(avatar_state) AS avatar,
        maxMerge(epeuid_state) AS epeuid,
        sumMerge(search_count_state) AS search_count
      FROM siem.fv_fgt_w_web_search_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale,
               srcintfrole, srcip, dstip, dstintfrole, policyid, policytype,
               keyword, hostname, f_user, userfield, srcuuid, dstuuid
)
GROUP BY _adomoid, dvid, timescale,
         srcintfrole, srcip, dstip, dstintfrole, policyid, policytype,
         keyword, hostname, f_user, userfield, srcuuid, dstuuid;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_w_web_search_day_mv_sp$SPID
TO siem.fv_fgt_w_web_search_day_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    srcintfrole,
    dstintfrole,
    policyid,
    policytype,
    keyword,
    hostname,
    f_user,
    userfield,
    srcip,
    dstip,
    srcuuid,
    dstuuid,
    maxState(avatar) AS avatar_state,
    maxState(epeuid) AS epeuid_state,
    sumState(search_count) AS search_count_state
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        srcintfrole,
        dstintfrole,
        policyid,
        policytype,
        keyword,
        hostname,
        f_user,
        userfield,
        srcip,
        dstip,
        srcuuid,
        dstuuid,
        maxMerge(avatar_state) AS avatar,
        maxMerge(epeuid_state) AS epeuid,
        sumMerge(search_count_state) AS search_count
      FROM siem.fv_fgt_w_web_search_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale,
               srcintfrole, srcip, dstip, dstintfrole, policyid, policytype,
               keyword, hostname, f_user, userfield, srcuuid, dstuuid
)
GROUP BY _adomoid, dvid, timescale,
         srcintfrole, srcip, dstip, dstintfrole, policyid, policytype,
         keyword, hostname, f_user, userfield, srcuuid, dstuuid;

ALTER TABLE siem.fv_fgt_w_web_search_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
