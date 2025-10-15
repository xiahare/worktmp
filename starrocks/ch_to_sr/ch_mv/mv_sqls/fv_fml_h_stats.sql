/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fml_h_stats",
    "datasource_mv": "fv_fml_h_stats_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fml_h_stats_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fml_h_stats_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fml_h_stats_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fml_h_stats_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fml_h_stats_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fml_h_stats_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fml_h_stats_5min_sp$SPID (
    timescale DateTime, dvid Int32,
    _adomoid UInt64,
    sender Nullable(String),
    recipient Nullable(String),
    classifier Nullable(String),
    virus Nullable(String),
    direction Nullable(String),
    message_length_state AggregateFunction(sum, Int64),
    scan_time_state AggregateFunction(sum, Float64),
    xfer_time_state AggregateFunction(sum, Float64),
    total_num_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, sender, recipient, classifier, virus, direction)
ORDER BY (_adomoid, dvid, timescale, sender, recipient, classifier, virus, direction)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fml_h_stats_hour_sp$SPID AS siem.fv_fml_h_stats_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fml_h_stats_day_sp$SPID AS siem.fv_fml_h_stats_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fml_h_stats_5min_mv_sp$SPID
TO siem.fv_fml_h_stats_5min_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(itime, 300, 0) AS timescale,
       sender,
       recipient,
       classifier,
       virus,
       direction,
       sumState(toInt64(message_length)) AS message_length_state,
       sumState(scan_time) AS scan_time_state,
       sumState(xfer_time) AS xfer_time_state,
       sumState(toInt64(total_num)) AS total_num_state
       FROM (
           SELECT
               itime,
               dvid,
               _adomoid,
               _devlogtype,
               $LOGFIELD-from-sender,
               $LOGFIELD-to-recipient,
               $LOGFIELD-classifier,
               $LOGFIELD-virus,
               $LOGFIELD-direction,
               (coalesce($LOGFIELD_NOALIAS-message_length, 0)) AS message_length,
               (coalesce($LOGFIELD_NOALIAS-scan_time, 0)) AS scan_time,
               (coalesce($LOGFIELD_NOALIAS-xfer_time, 0)) AS xfer_time,
               1 AS total_num
          FROM siem.ulog_sp$SPID
          WHERE  _devlogtype = 4007
)
GROUP BY _adomoid, dvid, timescale, sender, recipient, classifier, virus, direction;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fml_h_stats_hour_mv_sp$SPID
TO siem.fv_fml_h_stats_hour_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 3600, 0) AS timescale,
       sender,
       recipient,
       classifier,
       virus,
       direction,
       sumState(message_length) AS message_length_state,
       sumState(scan_time) AS scan_time_state,
       sumState(xfer_time) AS xfer_time_state,
       sumState(total_num) AS total_num_state
FROM (
   SELECT _adomoid, dvid,
       timescale,
       sender,
       recipient,
       classifier,
       virus,
       direction,
       sumMerge(message_length_state) AS message_length,
       sumMerge(scan_time_state) AS scan_time,
       sumMerge(xfer_time_state) AS xfer_time,
       sumMerge(total_num_state) AS total_num
    FROM siem.fv_fml_h_stats_5min_sp$SPID
    GROUP BY _adomoid, dvid, timescale, sender, recipient, classifier, virus, direction
)
GROUP BY _adomoid, dvid, timescale, sender, recipient, classifier, virus, direction;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fml_h_stats_day_mv_sp$SPID
TO siem.fv_fml_h_stats_day_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 28800, 0) AS timescale,
       sender,
       recipient,
       classifier,
       virus,
       direction,
       sumState(message_length) AS message_length_state,
       sumState(scan_time) AS scan_time_state,
       sumState(xfer_time) AS xfer_time_state,
       sumState(total_num) AS total_num_state
FROM (
   SELECT _adomoid, dvid,
       timescale,
       sender,
       recipient,
       classifier,
       virus,
       direction,
       sumMerge(message_length_state) AS message_length,
       sumMerge(scan_time_state) AS scan_time,
       sumMerge(xfer_time_state) AS xfer_time,
       sumMerge(total_num_state) AS total_num
    FROM siem.fv_fml_h_stats_hour_sp$SPID
    GROUP BY _adomoid, dvid, timescale, sender, recipient, classifier, virus, direction
)
GROUP BY _adomoid, dvid, timescale, sender, recipient, classifier, virus, direction;

ALTER TABLE siem.fv_fml_h_stats_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
