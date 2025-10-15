/*
{
    "type": "sp_mv",
    "version": "070600.3335",
    "name": "fv_fgt_e_event_summary",
    "datasource_mv": "fv_fgt_e_event_summary_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_e_event_summary_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_event_summary_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_event_summary_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_event_summary_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_event_summary_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_event_summary_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_event_summary_5min_sp$SPID (
    _adomoid UInt64,
    dvid Int32,
    timescale DateTime,
    level UInt8,
    subtype LowCardinality(Nullable(String)),
    eventname Nullable(String),
    count_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, subtype)
ORDER BY (_adomoid, dvid, timescale, subtype, eventname)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;


CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_event_summary_hour_sp$SPID AS siem.fv_fgt_e_event_summary_5min_sp$SPID;


CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_event_summary_day_sp$SPID AS siem.fv_fgt_e_event_summary_5min_sp$SPID;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_event_summary_5min_mv_sp$SPID
TO siem.fv_fgt_e_event_summary_5min_sp$SPID
AS SELECT 
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    level,
    subtype,
    eventname,
    sumState(toInt64(count)) AS count_state
FROM (
      SELECT
        _adomoid,
        dvid,
        itime AS timescale,
        $LOGFIELD-user,
        subtype,
        $LOGFIELD-logdesc,
        logdesc AS eventname,
        event_level_s2i($LOGFIELD_NOALIAS-level) AS level,
        1 AS count
      FROM siem.elog_sp$SPID
      WHERE _devlogtype= 5 AND logdesc IS NOT NULL
)
GROUP BY _adomoid, dvid, timescale, level, subtype, eventname;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_event_summary_hour_mv_sp$SPID
TO siem.fv_fgt_e_event_summary_hour_sp$SPID
AS SELECT 
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    level,
    subtype,
    eventname,
    sumState(count) AS count_state
FROM (
      SELECT
        _adomoid,
        dvid,
        fv_timescale_func(timescale, 3600, 0) AS timescale,
        level,
        subtype,
        eventname,
        sumMerge(count_state) AS count
      FROM siem.fv_fgt_e_event_summary_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale, level, subtype, eventname
)
GROUP BY _adomoid, dvid, timescale, level, subtype, eventname;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_event_summary_day_mv_sp$SPID
TO siem.fv_fgt_e_event_summary_day_sp$SPID
AS SELECT 
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    level,
    subtype,
    eventname,
    sumState(count) AS count_state
FROM (
      SELECT
        _adomoid,
        dvid,
        fv_timescale_func(timescale, 28800, 0) AS timescale,
        level,
        subtype,
        eventname,
        sumMerge(count_state) AS count
      FROM siem.fv_fgt_e_event_summary_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale, level, subtype, eventname
)
GROUP BY _adomoid, dvid, timescale, level, subtype, eventname;

ALTER TABLE siem.fv_fgt_e_event_summary_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
