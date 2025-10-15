/*
{
    "type": "sp_mv",
    "version": "070602.3405",
    "name": "fv_fdd_a_src_dst",
    "datasource_mv": "fv_fdd_a_src_dst_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fdd_a_src_dst_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fdd_a_src_dst_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fdd_a_src_dst_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fdd_a_src_dst_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fdd_a_src_dst_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fdd_a_src_dst_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fdd_a_src_dst_5min_sp$SPID (
    _adomoid UInt64,
    dvid Int32,
    timescale DateTime,
    sip Nullable(IPv6),
    dip Nullable(IPv6),
    type LowCardinality(String),
    description Nullable(String),
    dropcount_state AggregateFunction(sum, Nullable(UInt64))
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, sip, dip)
ORDER BY (_adomoid, dvid, timescale, sip, dip, type, description)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fdd_a_src_dst_hour_sp$SPID AS siem.fv_fdd_a_src_dst_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fdd_a_src_dst_day_sp$SPID AS siem.fv_fdd_a_src_dst_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fdd_a_src_dst_5min_mv_sp$SPID
TO siem.fv_fdd_a_src_dst_5min_sp$SPID
AS SELECT
    _adomoid,
    dvid,
    fv_timescale_func(itime, 300, 0) AS timescale,
    sip,
    dip,
    type,
    description,
    sumState(dropcount) AS dropcount_state
    FROM (
       SELECT _adomoid,
           dvid,
           itime,
           $LOGFIELD-sip,
           $LOGFIELD-dip,
           $LOGFIELD-type,
           $LOGFIELD-description,
           $LOGFIELD-dropcount
      FROM siem.ulog_sp$SPID
      WHERE _devlogtype = 11001
)
GROUP BY _adomoid, dvid, timescale,
         sip, dip, type, description;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fdd_a_src_dst_hour_mv_sp$SPID
TO siem.fv_fdd_a_src_dst_hour_sp$SPID
AS SELECT
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    sip,
    dip,
    type,
    description,
    sumState(dropcount) AS dropcount_state
    FROM (
        SELECT
        _adomoid,
        dvid,
        timescale,
        sip,
        dip,
        type,
        description,
        sumMerge(dropcount_state) AS dropcount
      FROM siem.fv_fdd_a_src_dst_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale,
               sip, dip, type, description
)
GROUP BY _adomoid, dvid, timescale,
         sip, dip, type, description;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fdd_a_src_dst_day_mv_sp$SPID
TO siem.fv_fdd_a_src_dst_day_sp$SPID
AS SELECT
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    sip,
    dip,
    type,
    description,
    sumState(dropcount) AS dropcount_state
    FROM (
        SELECT
        _adomoid,
        dvid,
        timescale,
        sip,
        dip,
        type,
        description,
        sumMerge(dropcount_state) AS dropcount
      FROM siem.fv_fdd_a_src_dst_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale,
               sip, dip, type, description
)
GROUP BY _adomoid, dvid, timescale,
         sip, dip, type, description;

ALTER TABLE siem.fv_fdd_a_src_dst_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
