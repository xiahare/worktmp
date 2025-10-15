/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_v_fsa_verdict",
    "datasource_mv": "fv_fgt_v_fsa_verdict_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_verdict_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_verdict_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_verdict_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_verdict_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_verdict_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_fsa_verdict_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_v_fsa_verdict_5min_sp$SPID (
    timescale DateTime, dvid Int32, _adomoid UInt64,
    fctuid Nullable(UUID),
    unauthuser LowCardinality(Nullable(String)),
    user_src Nullable(String),
    verdict_malicious_cnt_state AggregateFunction(sum, Int64),
    verdict_suspicious_cnt_state AggregateFunction(sum, Int64),
    verdict_clean_cnt_state AggregateFunction(sum, Int64),
    total_verdict_cnt_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, timescale, dvid, fctuid)
ORDER BY (_adomoid, timescale, dvid, fctuid)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_v_fsa_verdict_hour_sp$SPID AS siem.fv_fgt_v_fsa_verdict_5min_sp$SPID;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_v_fsa_verdict_day_sp$SPID AS siem.fv_fgt_v_fsa_verdict_5min_sp$SPID;
CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_v_fsa_verdict_5min_mv_sp$SPID
TO siem.fv_fgt_v_fsa_verdict_5min_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    fctuid, unauthuser, user_src,
    sumState(toInt64(verdict_malicious_cnt)) AS verdict_malicious_cnt_state,
    sumState(toInt64(verdict_suspicious_cnt)) AS verdict_suspicious_cnt_state,
    sumState(toInt64(verdict_clean_cnt)) AS verdict_clean_cnt_state,
    sumState(toInt64(total_verdict_cnt)) AS total_verdict_cnt_state
    FROM (
       SELECT
        _adomoid, dvid,
        itime AS timescale,
        $LOGFIELD-fctuid,
        $LOGFIELD-unauthuser,
        $LOGFIELD-srcip,
        $LOGFIELD-user,
        $LOGFIELD-fsaverdict,
        $LOGFIELD-dtype,
        coalesce(nullifna(`user`), nullifna(`unauthuser`), toString(assumeNotNull(srcip))) AS user_src,
        (CASE WHEN fsaverdict = 'malicious' THEN 1 ELSE 0 END) AS verdict_malicious_cnt,
        (CASE WHEN fsaverdict IN ('high risk', 'medium risk', 'low risk') THEN 1 ELSE 0 END) AS verdict_suspicious_cnt,
        (CASE WHEN fsaverdict = 'clean' THEN 1 ELSE 0 END) AS verdict_clean_cnt,
        1 AS total_verdict_cnt
      FROM siem.ulog_sp$SPID
      WHERE _devlogtype = 11 AND dtype='fortisandbox' AND fsaverdict IS NOT NULL
)
GROUP BY _adomoid, dvid, timescale,
         fctuid, unauthuser, user_src;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_v_fsa_verdict_hour_mv_sp$SPID
TO siem.fv_fgt_v_fsa_verdict_hour_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    fctuid, unauthuser, user_src,
    sumState(verdict_malicious_cnt) AS verdict_malicious_cnt_state,
    sumState(verdict_suspicious_cnt) AS verdict_suspicious_cnt_state,
    sumState(verdict_clean_cnt) AS verdict_clean_cnt_state,
    sumState(total_verdict_cnt) AS total_verdict_cnt_state
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        fctuid, unauthuser, user_src,
        sumMerge(verdict_malicious_cnt_state) AS verdict_malicious_cnt,
        sumMerge(verdict_suspicious_cnt_state) AS verdict_suspicious_cnt,
        sumMerge(verdict_clean_cnt_state) AS verdict_clean_cnt,
        sumMerge(total_verdict_cnt_state) AS total_verdict_cnt
      FROM siem.fv_fgt_v_fsa_verdict_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale, fctuid, unauthuser, user_src
)
GROUP BY _adomoid, dvid, timescale, fctuid, unauthuser, user_src;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_v_fsa_verdict_day_mv_sp$SPID
TO siem.fv_fgt_v_fsa_verdict_day_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    fctuid, unauthuser, user_src,
    sumState(verdict_malicious_cnt) AS verdict_malicious_cnt_state,
    sumState(verdict_suspicious_cnt) AS verdict_suspicious_cnt_state,
    sumState(verdict_clean_cnt) AS verdict_clean_cnt_state,
    sumState(total_verdict_cnt) AS total_verdict_cnt_state
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        fctuid, unauthuser, user_src,
        sumMerge(verdict_malicious_cnt_state) AS verdict_malicious_cnt,
        sumMerge(verdict_suspicious_cnt_state) AS verdict_suspicious_cnt,
        sumMerge(verdict_clean_cnt_state) AS verdict_clean_cnt,
        sumMerge(total_verdict_cnt_state) AS total_verdict_cnt
      FROM siem.fv_fgt_v_fsa_verdict_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale, fctuid, unauthuser, user_src
)
GROUP BY _adomoid, dvid, timescale, fctuid, unauthuser, user_src;

ALTER TABLE siem.fv_fgt_v_fsa_verdict_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
