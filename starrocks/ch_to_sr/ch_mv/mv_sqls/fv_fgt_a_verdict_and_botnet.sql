/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_a_verdict_and_botnet",
    "datasource_mv": "fv_fgt_a_verdict_and_botnet_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_a_verdict_and_botnet_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_verdict_and_botnet_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_verdict_and_botnet_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_verdict_and_botnet_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_verdict_and_botnet_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_a_verdict_and_botnet_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_a_verdict_and_botnet_5min_sp$SPID (
    timescale DateTime, dvid Int32, _adomoid UInt64,
    eventtype LowCardinality(Nullable(String)),
    srcip Nullable(IPv6),
    dstip Nullable(IPv6),
    srcintfrole LowCardinality(Nullable(String)),
    dstintfrole LowCardinality(Nullable(String)),
    dtime_state AggregateFunction(max, DateTime),
    botnet_cnt_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, timescale, dvid)
ORDER BY (_adomoid, timescale, dvid, eventtype, srcip, dstip, srcintfrole, dstintfrole)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_a_verdict_and_botnet_hour_sp$SPID AS siem.fv_fgt_a_verdict_and_botnet_5min_sp$SPID;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_a_verdict_and_botnet_day_sp$SPID AS siem.fv_fgt_a_verdict_and_botnet_5min_sp$SPID;
CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_a_verdict_and_botnet_5min_mv_sp$SPID
TO siem.fv_fgt_a_verdict_and_botnet_5min_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    eventtype,
    srcip,
    dstip,
    srcintfrole,
    dstintfrole,
    maxState(dtime) AS dtime_state,
    sumState(toInt64(botnet_cnt)) AS botnet_cnt_state
    FROM (
        SELECT 
            _adomoid, dvid,
            itime AS timescale,
            $LOGFIELD-eventtype,
            $LOGFIELD-srcip,
            $LOGFIELD-dstip,
            $LOGFIELD-srcintfrole,
            $LOGFIELD-dstintfrole,
            dtime,
            1 AS botnet_cnt
            FROM siem.ulog_sp$SPID
            WHERE _devlogtype = 1 AND eventtype='botnet'
)
GROUP BY _adomoid, timescale, dvid, eventtype, srcip, dstip, srcintfrole, dstintfrole;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_a_verdict_and_botnet_hour_mv_sp$SPID
TO siem.fv_fgt_a_verdict_and_botnet_hour_sp$SPID
AS SELECT
    _adomoid, 
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    eventtype,
    srcip,
    dstip,
    srcintfrole,
    dstintfrole,
    maxState(dtime) AS dtime_state,
    sumState(botnet_cnt) AS botnet_cnt_state
    FROM (
       SELECT 
        _adomoid, dvid,
        fv_timescale_func(timescale, 3600, 0) AS timescale,
        eventtype,
        srcip,
        dstip,
        srcintfrole,
        dstintfrole,
        maxMerge(dtime_state) AS dtime,
        sumMerge(botnet_cnt_state) AS botnet_cnt
       FROM siem.fv_fgt_a_verdict_and_botnet_5min_sp$SPID
       GROUP BY _adomoid, timescale, dvid,
                eventtype, srcip, dstip, srcintfrole, dstintfrole
    ) t
GROUP BY _adomoid, timescale, dvid,
         eventtype, srcip, dstip, srcintfrole, dstintfrole;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_a_verdict_and_botnet_day_mv_sp$SPID
TO siem.fv_fgt_a_verdict_and_botnet_day_sp$SPID
AS SELECT
    _adomoid, 
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    eventtype,
    srcip,
    dstip,
    srcintfrole,
    dstintfrole,
    maxState(dtime) AS dtime_state,
    sumState(botnet_cnt) AS botnet_cnt_state
    FROM (
       SELECT 
        _adomoid, dvid,
        fv_timescale_func(timescale, 3600, 0) AS timescale,
        eventtype,
        srcip,
        dstip,
        srcintfrole,
        dstintfrole,
        maxMerge(dtime_state) AS dtime,
        sumMerge(botnet_cnt_state) AS botnet_cnt
       FROM siem.fv_fgt_a_verdict_and_botnet_hour_sp$SPID
       GROUP BY _adomoid, timescale, dvid,
                eventtype, srcip, dstip, srcintfrole, dstintfrole
    ) t
GROUP BY _adomoid, timescale, dvid,
         eventtype, srcip, dstip, srcintfrole, dstintfrole;

ALTER TABLE siem.fv_fgt_a_verdict_and_botnet_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
