/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_t_iot_inventory",
    "datasource_mv": "fv_fgt_t_iot_inventory_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_t_iot_inventory_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_iot_inventory_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_iot_inventory_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_iot_inventory_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_iot_inventory_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_iot_inventory_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_iot_inventory_5min_sp$SPID (
    timescale DateTime, dvid Int32, _adomoid UInt64,
    srcmac Nullable(String),
    devtype LowCardinality(Nullable(String)),
    srchwvendor Nullable(String),
    srchwversion Nullable(String),
    bandwidth_state AggregateFunction(sum, Int64),
    traffic_in_state AggregateFunction(sum, Int64),
    traffic_out_state AggregateFunction(sum, Int64),
    session_block_state AggregateFunction(sum, Int64),
    sessions_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, timescale, dvid, srcmac, devtype)
ORDER BY (_adomoid, timescale, dvid,
          srcmac, devtype, srchwvendor, srchwversion)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_iot_inventory_hour_sp$SPID AS siem.fv_fgt_t_iot_inventory_5min_sp$SPID;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_iot_inventory_day_sp$SPID AS siem.fv_fgt_t_iot_inventory_5min_sp$SPID;
CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_iot_inventory_5min_mv_sp$SPID
TO siem.fv_fgt_t_iot_inventory_5min_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    srcmac, devtype, srchwvendor, srchwversion,
    sumState(toInt64(bandwidth)) AS bandwidth_state, sumState(toInt64(traffic_in)) AS traffic_in_state,
    sumState(toInt64(traffic_out)) AS traffic_out_state, sumState(toInt64(session_block)) AS session_block_state,
    sumState(toInt64(sessions)) AS sessions_state
    FROM (
       SELECT
        _adomoid, dvid,
        itime AS timescale,
        $LOGFIELD-srcmac,
        $LOGFIELD-devtype,
        $LOGFIELD-srchwvendor,
        $LOGFIELD-srchwversion,
        $LOGFIELD-sentbyte,
        $LOGFIELD-rcvdbyte,
        $LOGFIELD-sentdelta,
        $LOGFIELD-rcvddelta,
        coalesce(sentdelta, sentbyte, 0)+coalesce(rcvddelta, rcvdbyte, 0) AS bandwidth,
        coalesce(rcvddelta, rcvdbyte, 0) AS traffic_in,
        coalesce(sentdelta, sentbyte, 0) AS traffic_out,
        CAST(( CASE WHEN(bitAnd(logflag, 2) > 0) THEN 1 ELSE 0 END), 'Int64') AS session_block,
        CAST(( CASE WHEN(bitAnd(logflag, 1) > 0) THEN 1 ELSE 0 END), 'Int64') AS sessions
      FROM siem.tlog_sp$SPID
      WHERE bitAnd(logflag, bitOr(1, 32)) > 0 AND _devlogtype = 10
            AND devtype = 'IoT'
)
GROUP BY _adomoid, timescale, dvid,
         srcmac, devtype, srchwvendor, srchwversion;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_iot_inventory_hour_mv_sp$SPID
TO siem.fv_fgt_t_iot_inventory_hour_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    srcmac, devtype, srchwvendor, srchwversion,
    sumState(bandwidth) AS bandwidth_state, sumState(traffic_in) AS traffic_in_state,
    sumState(traffic_out) AS traffic_out_state, sumState(session_block) AS session_block_state,
    sumState(sessions) AS sessions_state
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        srcmac, devtype, srchwvendor, srchwversion,
        sumMerge(bandwidth_state) AS bandwidth, sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(traffic_out_state) AS traffic_out, sumMerge(session_block_state) AS session_block,
        sumMerge(sessions_state) AS sessions
      FROM siem.fv_fgt_t_iot_inventory_5min_sp$SPID
      GROUP BY _adomoid, timescale, dvid,
               srcmac, devtype, srchwvendor, srchwversion
)
GROUP BY _adomoid, timescale, dvid,
         srcmac, devtype, srchwvendor, srchwversion;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_iot_inventory_day_mv_sp$SPID
TO siem.fv_fgt_t_iot_inventory_day_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    srcmac, devtype, srchwvendor, srchwversion,
    sumState(bandwidth) AS bandwidth_state, sumState(traffic_in) AS traffic_in_state,
    sumState(traffic_out) AS traffic_out_state, sumState(session_block) AS session_block_state,
    sumState(sessions) AS sessions_state
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        srcmac, devtype, srchwvendor, srchwversion,
        sumMerge(bandwidth_state) AS bandwidth, sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(traffic_out_state) AS traffic_out, sumMerge(session_block_state) AS session_block,
        sumMerge(sessions_state) AS sessions
      FROM siem.fv_fgt_t_iot_inventory_hour_sp$SPID
      GROUP BY _adomoid, timescale, dvid,
               srcmac, devtype, srchwvendor, srchwversion
)
GROUP BY _adomoid, timescale, dvid,
         srcmac, devtype, srchwvendor, srchwversion;

ALTER TABLE siem.fv_fgt_t_iot_inventory_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
