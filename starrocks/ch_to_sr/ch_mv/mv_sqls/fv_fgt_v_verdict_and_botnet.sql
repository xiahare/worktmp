/*
{
    "type": "sp_mv",
    "version": "070601.3372",
    "name": "fv_fgt_v_verdict_and_botnet",
    "datasource_mv": "fv_fgt_v_verdict_and_botnet_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_v_verdict_and_botnet_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_verdict_and_botnet_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_verdict_and_botnet_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_verdict_and_botnet_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_verdict_and_botnet_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_verdict_and_botnet_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_v_verdict_and_botnet_5min_sp$SPID (
    timescale DateTime, dvid Int32, _adomoid UInt64,
    f_user Nullable(String),
    user_type Nullable(String),
    virus LowCardinality(Nullable(String)),
    virusid Nullable(UInt32),
    eventtype LowCardinality(Nullable(String)),
    filename Nullable(String),
    fsaverdict Nullable(String),
    srcip Nullable(IPv6),
    dstip Nullable(IPv6),
    analyticscksum Nullable(String),
    srcintfrole LowCardinality(Nullable(String)),
    dstintfrole LowCardinality(Nullable(String)),
    dtime_state AggregateFunction(max, DateTime),
    botnet_cnt_state AggregateFunction(sum, Int64),
    analytics_cnt_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, timescale, dvid, f_user, user_type, virus)
ORDER BY (_adomoid, timescale, dvid, f_user, user_type, virus, virusid,
          eventtype, filename, fsaverdict, srcip, dstip, analyticscksum, srcintfrole, dstintfrole)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_v_verdict_and_botnet_hour_sp$SPID AS siem.fv_fgt_v_verdict_and_botnet_5min_sp$SPID;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_v_verdict_and_botnet_day_sp$SPID AS siem.fv_fgt_v_verdict_and_botnet_5min_sp$SPID;
CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_v_verdict_and_botnet_5min_mv_sp$SPID
TO siem.fv_fgt_v_verdict_and_botnet_5min_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    f_user,
    user_type,
    virus,
    virusid,
    eventtype,
    filename,
    fsaverdict,
    srcip,
    dstip,
    analyticscksum,
    srcintfrole,
    dstintfrole,
    maxState(dtime) AS dtime_state,
    sumState(toInt64(botnet_cnt)) AS botnet_cnt_state,
    sumState(toInt64(analytics_cnt)) AS analytics_cnt_state
    FROM (
        SELECT 
            _adomoid, dvid,
            itime AS timescale,
            $LOGFIELD-user,
            $LOGFIELD-unauthuser,
            coalesce(nullifna(`user`), nullifna(`unauthuser`)) AS f_user,
            (CASE WHEN `user` IS NOT NULL THEN 'auth' ELSE NULL END) AS user_type,
            $LOGFIELD-virus,
            $LOGFIELD-virusid,
            $LOGFIELD-eventtype,
            $LOGFIELD-filename,
            $LOGFIELD-srcip,
            $LOGFIELD-dstip,
            $LOGFIELD-analyticscksum,
            dtime,
            $LOGFIELD-fsaverdict,
            $LOGFIELD-srcintfrole,
            $LOGFIELD-dstintfrole,
            (CASE WHEN eventtype='botnet' THEN 1 ELSE 0 END) AS botnet_cnt,
            (CASE WHEN eventtype='analytics' THEN 1 ELSE 0 END) AS analytics_cnt
            FROM siem.ulog_sp$SPID
            WHERE _devlogtype = 11 AND (eventtype='analytics' AND analyticscksum IS NOT NULL) OR eventtype ='botnet'
)
GROUP BY _adomoid, timescale, dvid,
         f_user, user_type, virus, virusid,
         eventtype, filename, fsaverdict, srcip, dstip, analyticscksum, srcintfrole, dstintfrole;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_v_verdict_and_botnet_hour_mv_sp$SPID
TO siem.fv_fgt_v_verdict_and_botnet_hour_sp$SPID
AS SELECT
    _adomoid, 
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    dvid, f_user,
    user_type,
    virus,
    virusid,
    eventtype,
    filename,
    fsaverdict,
    srcip,
    dstip,
    analyticscksum,
    srcintfrole,
    dstintfrole,
    maxState(dtime) AS dtime_state,
    sumState(botnet_cnt) AS botnet_cnt_state,
    sumState(analytics_cnt) AS analytics_cnt_state
    FROM (
       SELECT 
        _adomoid, dvid,
        fv_timescale_func(timescale, 3600, 0) AS timescale,
        f_user,
        user_type,
        virus,
        virusid,
        eventtype,
        filename,
        fsaverdict,
        srcip,
        dstip,
        analyticscksum,
        srcintfrole,
        dstintfrole,
        maxMerge(dtime_state) AS dtime,
        sumMerge(botnet_cnt_state) AS botnet_cnt,
        sumMerge(analytics_cnt_state) AS analytics_cnt
       FROM siem.fv_fgt_v_verdict_and_botnet_5min_sp$SPID
       GROUP BY _adomoid, timescale, dvid,
                f_user, user_type, virus, virusid,
                eventtype, filename, fsaverdict, srcip, dstip, analyticscksum, srcintfrole, dstintfrole
    ) t
GROUP BY _adomoid, timescale, dvid,
         f_user, user_type, virus, virusid,
         eventtype, filename, fsaverdict, srcip, dstip, analyticscksum, srcintfrole, dstintfrole;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_v_verdict_and_botnet_day_mv_sp$SPID
TO siem.fv_fgt_v_verdict_and_botnet_day_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    f_user,
    user_type,
    virus,
    virusid,
    eventtype,
    filename,
    fsaverdict,
    srcip,
    dstip,
    analyticscksum,
    srcintfrole,
    dstintfrole,
    maxState(dtime) AS dtime_state,
    sumState(botnet_cnt) AS botnet_cnt_state,
    sumState(analytics_cnt) AS analytics_cnt_state
    FROM (
       SELECT 
        _adomoid, dvid,
        fv_timescale_func(timescale, 3600, 0) AS timescale,
        f_user,
        user_type,
        virus,
        virusid,
        eventtype,
        filename,
        fsaverdict,
        srcip,
        dstip,
        analyticscksum,
        srcintfrole,
        dstintfrole,
        maxMerge(dtime_state) AS dtime,
        sumMerge(botnet_cnt_state) AS botnet_cnt,
        sumMerge(analytics_cnt_state) AS analytics_cnt
       FROM siem.fv_fgt_v_verdict_and_botnet_hour_sp$SPID
       GROUP BY _adomoid, timescale, dvid,
                f_user, user_type, virus, virusid,
                eventtype, filename, fsaverdict, srcip, dstip, analyticscksum, srcintfrole, dstintfrole
    ) t
GROUP BY _adomoid, timescale, dvid,
         f_user, user_type, virus, virusid,
         eventtype, filename, fsaverdict, srcip, dstip, analyticscksum, srcintfrole, dstintfrole;

ALTER TABLE siem.fv_fgt_v_verdict_and_botnet_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
