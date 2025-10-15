/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_v_fsa_verdict_avatar",
    "datasource_mv": "fv_fgt_v_fsa_verdict_avatar_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_verdict_avatar_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_verdict_avatar_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_verdict_avatar_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_verdict_avatar_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_verdict_avatar_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_verdict_avatar_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_v_fsa_verdict_avatar_5min_sp$SPID (
    timescale DateTime, dvid Int32, _adomoid UInt64,
    f_user_state AggregateFunction(max, Nullable(String)),
    srcip Nullable(IPv6),
    avatar_state  AggregateFunction(max, Nullable(String)),
    epeuid_state  AggregateFunction(max, Nullable(String)),
    fsaverdict_state  AggregateFunction(max, Nullable(String)),
    analyticscksum Nullable(String)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, timescale, dvid, srcip)
ORDER BY (_adomoid, timescale, dvid, srcip, analyticscksum)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_v_fsa_verdict_avatar_hour_sp$SPID AS siem.fv_fgt_v_fsa_verdict_avatar_5min_sp$SPID;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_v_fsa_verdict_avatar_day_sp$SPID AS siem.fv_fgt_v_fsa_verdict_avatar_5min_sp$SPID;
CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_v_fsa_verdict_avatar_5min_mv_sp$SPID
TO siem.fv_fgt_v_fsa_verdict_avatar_5min_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    maxState(f_user) AS f_user_state,
    srcip,
    maxState(avatar) AS avatar_state,
    maxState(epeuid) AS epeuid_state,
    maxState(fsaverdict) AS fsaverdict_state,
    analyticscksum
    FROM (
       SELECT
        _adomoid, dvid,
        itime AS timescale,
        (CASE WHEN fctuid IS NOT NULL AND unauthuser IS NOT NULL THEN CONCAT(toString(fctuid), ',', unauthuser) ELSE NULL END) AS avatar,
        $LOGFIELD-fctuid,
        $LOGFIELD-unauthuser,
        $LOGFIELD-srcip,
        $LOGFIELD-user,
        $LOGFIELD-fsaverdict,
        $LOGFIELD-eventtype,
        ucase($LOGFIELD_NOALIAS-analyticscksum) AS analyticscksum,
        ( CASE WHEN epid > 1023 AND euid IS NOT NULL THEN CONCAT(toString(epid), ',', toString(euid)) ELSE NULL END) AS epeuid,
        coalesce(nullifna(`user`), nullifna(`unauthuser`)) AS f_user
      FROM siem.ulog_sp$SPID
      WHERE _devlogtype = 11 AND eventtype='analytics' AND analyticscksum IS NOT NULL
)
GROUP BY _adomoid, dvid, timescale,
         srcip, analyticscksum; 

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_v_fsa_verdict_avatar_hour_mv_sp$SPID
TO siem.fv_fgt_v_fsa_verdict_avatar_hour_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    maxState(f_user) AS f_user_state,
    srcip,
    maxState(avatar) AS avatar_state,
    maxState(epeuid) AS epeuid_state,
    maxState(fsaverdict) AS fsaverdict_state,
    analyticscksum
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        maxMerge(f_user_state) AS f_user,
        srcip,
        maxMerge(avatar_state) AS avatar,
        maxMerge(epeuid_state) AS epeuid,
        maxMerge(fsaverdict_state) AS fsaverdict,
        analyticscksum
      FROM siem.fv_fgt_v_fsa_verdict_avatar_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale, srcip, analyticscksum
)
GROUP BY _adomoid, dvid, timescale, srcip, analyticscksum;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_v_fsa_verdict_avatar_day_mv_sp$SPID
TO siem.fv_fgt_v_fsa_verdict_avatar_day_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    maxState(f_user) AS f_user_state,
    srcip,
    maxState(avatar) AS avatar_state,
    maxState(epeuid) AS epeuid_state,
    maxState(fsaverdict) AS fsaverdict_state,
    analyticscksum
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        maxMerge(f_user_state) AS f_user,
        srcip,
        maxMerge(avatar_state) AS avatar,
        maxMerge(epeuid_state) AS epeuid,
        maxMerge(fsaverdict_state) AS fsaverdict,
        analyticscksum
      FROM siem.fv_fgt_v_fsa_verdict_avatar_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale, srcip, analyticscksum
)
GROUP BY _adomoid, dvid, timescale, srcip, analyticscksum;

ALTER TABLE siem.fv_fgt_v_fsa_verdict_avatar_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
