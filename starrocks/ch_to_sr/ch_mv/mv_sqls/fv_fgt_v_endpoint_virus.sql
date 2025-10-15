/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_v_endpoint_virus",
    "datasource_mv": "fv_fgt_v_endpoint_virus_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_v_endpoint_virus_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_endpoint_virus_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_endpoint_virus_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_endpoint_virus_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_endpoint_virus_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_v_endpoint_virus_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_v_endpoint_virus_5min_sp$SPID (
    timescale DateTime, dvid Int32, _adomoid UInt64,
    epid Nullable(Int32),
    euid Int32,
    srcintf LowCardinality(Nullable(String)),
    virus LowCardinality(Nullable(String)),
    virusid Nullable(Int32),
    malware_type LowCardinality(Nullable(String)),
    dtime_state AggregateFunction(max, DateTime),
    events_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, timescale, dvid, epid, euid, srcintf)
ORDER BY (_adomoid, timescale,  dvid,
          epid, euid, srcintf, virus, virusid, malware_type)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_v_endpoint_virus_hour_sp$SPID AS siem.fv_fgt_v_endpoint_virus_5min_sp$SPID;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_v_endpoint_virus_day_sp$SPID AS siem.fv_fgt_v_endpoint_virus_5min_sp$SPID;
CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_v_endpoint_virus_5min_mv_sp$SPID
TO siem.fv_fgt_v_endpoint_virus_5min_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    epid, euid, srcintf, virus, virusid, malware_type,
    maxState(dtime) AS dtime_state,
    sumState(toInt64(events)) AS events_state
    FROM (
       SELECT
        _adomoid, dvid,
        itime AS timescale,
        epid, euid,
        $LOGFIELD-srcintf,
        $LOGFIELD-virus,
        $LOGFIELD-virusid,
        $LOGFIELD-eventtype,
        (CASE WHEN eventtype='botnet' THEN 'Botnet C&C' ELSE 'Virus' END) AS malware_type,
        dtime,
        1 AS events
      FROM siem.ulog_sp$SPID
      WHERE _devlogtype = 11 AND nullifna(virus) IS NOT NULL
)
GROUP BY _adomoid, dvid, timescale,
         epid, euid, srcintf, virus, virusid, malware_type;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_v_endpoint_virus_hour_mv_sp$SPID
TO siem.fv_fgt_v_endpoint_virus_hour_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    epid, euid, srcintf, virus, virusid, malware_type,
    maxState(dtime) AS dtime_state,
    sumState(events) AS events_state
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        epid, euid, srcintf, virus, virusid, malware_type,
        maxMerge(dtime_state) AS dtime,
        sumMerge(events_state) AS events
      FROM siem.fv_fgt_v_endpoint_virus_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale,
               epid, euid, srcintf, virus, virusid, malware_type
)
GROUP BY _adomoid, dvid, timescale,
         epid, euid, srcintf, virus, virusid, malware_type;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_v_endpoint_virus_day_mv_sp$SPID
TO siem.fv_fgt_v_endpoint_virus_day_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    epid, euid, srcintf, virus, virusid, malware_type,
    maxState(dtime) AS dtime_state,
    sumState(events) AS events_state
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        epid, euid, srcintf, virus, virusid, malware_type,
        maxMerge(dtime_state) AS dtime,
        sumMerge(events_state) AS events
      FROM siem.fv_fgt_v_endpoint_virus_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale,
               epid, euid, srcintf, virus, virusid, malware_type
)
GROUP BY _adomoid, dvid, timescale,
         epid, euid, srcintf, virus, virusid, malware_type;

ALTER TABLE siem.fv_fgt_v_endpoint_virus_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
