/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_e_rogue_aps",
    "datasource_mv": "fv_fgt_e_rogue_aps_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_e_rogue_aps_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_rogue_aps_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_rogue_aps_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_rogue_aps_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_rogue_aps_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_rogue_aps_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_rogue_aps_5min_sp$SPID (
    _adomoid UInt64,
    dvid Int32,
    timescale DateTime,
    ssid Nullable(String),
    sec_mode Nullable(String),
    manuf Nullable(String),
    channel Nullable(UInt8),
    radioband Nullable(String),
    onwire Nullable(String),
    first_seen_state AggregateFunction(min, DateTime),
    last_seen_state AggregateFunction(max, DateTime),
    events_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, ssid)
ORDER BY (_adomoid, dvid, timescale, ssid, sec_mode,
          manuf, channel, onwire, radioband)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_rogue_aps_hour_sp$SPID AS siem.fv_fgt_e_rogue_aps_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_rogue_aps_day_sp$SPID AS siem.fv_fgt_e_rogue_aps_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_rogue_aps_5min_mv_sp$SPID
TO siem.fv_fgt_e_rogue_aps_5min_sp$SPID
AS SELECT
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    ssid,
    sec_mode,
    manuf,
    channel,
    radioband,
    onwire,
    minState(dtime) AS first_seen_state,
    maxState(dtime) AS last_seen_state,
    sumState(toInt64(count)) AS events_state
FROM (
      SELECT
        _adomoid,
        dvid,
        _devlogtype,
        itime AS timescale,
        $LOGFIELD-ssid,
        $LOGFIELD-manuf,
        $LOGFIELD-channel,
        $LOGFIELD-radioband,
        $LOGFIELD-onwire,
        $LOGFIELD-bssid,
        $LOGFIELD-security,
        $LOGFIELD-securitymode,
        dtime,
        1 AS count,
        coalesce(nullifna(security), securitymode) AS sec_mode
      FROM siem.elog_sp$SPID
      WHERE bssid IS NOT NULL
            AND logid_to_int(logid) IN (43527, 43521, 43525, 43563, 43564, 43565, 43566, 43569, 43570, 43571, 43582, 43583, 43584, 43585)
            AND _devlogtype = 5
)
GROUP BY _adomoid, dvid, timescale, ssid, sec_mode,
        manuf, channel, onwire, radioband;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_rogue_aps_hour_mv_sp$SPID
TO siem.fv_fgt_e_rogue_aps_hour_sp$SPID
AS SELECT
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    ssid,
    sec_mode,
    manuf,
    channel,
    radioband,
    onwire,
    minState(first_seen) AS first_seen_state,
    maxState(last_seen) AS last_seen_state,
    sumState(events) AS events_state
FROM (
      SELECT
        _adomoid,
        dvid,
        timescale,
        ssid,
        sec_mode,
        manuf,
        channel,
        radioband,
        onwire,
        minMerge(first_seen_state) AS first_seen,
        maxMerge(last_seen_state) AS last_seen,
        sumMerge(events_state) AS events
      FROM siem.fv_fgt_e_rogue_aps_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale, ssid, sec_mode,
               manuf, channel, onwire, radioband
)
GROUP BY _adomoid, dvid, timescale, ssid, sec_mode,
         manuf, channel, onwire, radioband;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_rogue_aps_day_mv_sp$SPID
TO siem.fv_fgt_e_rogue_aps_day_sp$SPID
AS SELECT 
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    ssid,
    sec_mode,
    manuf,
    channel,
    radioband,
    onwire,
    minState(first_seen) AS first_seen_state,
    maxState(last_seen) AS last_seen_state,
    sumState(events) AS events_state
FROM (
      SELECT
        _adomoid,
        dvid,
        timescale,
        ssid,
        sec_mode,
        manuf,
        channel,
        radioband,
        onwire,
        minMerge(first_seen_state) AS first_seen,
        maxMerge(last_seen_state) AS last_seen,
        sumMerge(events_state) AS events
      FROM siem.fv_fgt_e_rogue_aps_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale, ssid, sec_mode,
               manuf, channel, onwire, radioband
)
GROUP BY _adomoid, dvid, timescale, ssid, sec_mode,
         manuf, channel, onwire, radioband;

ALTER TABLE siem.fv_fgt_e_rogue_aps_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
