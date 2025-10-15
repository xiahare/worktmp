/*
{
    "type": "sp_mv",
    "version": "070600.3447",
    "name": "fv_fgt_e_resource_usage",
    "datasource_mv": "fv_fgt_e_resource_usage_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_e_resource_usage_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_resource_usage_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_resource_usage_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_resource_usage_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_resource_usage_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_resource_usage_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_resource_usage_5min_sp$SPID (
    _adomoid UInt64,
    dvid Int32,
    slot Nullable(Int8),
    role Nullable(String),
    timescale DateTime,
    total_mem_state AggregateFunction(sum, Int64),
    mem_peak_state AggregateFunction(max, UInt8),
    total_disk_state AggregateFunction(sum, Int64),
    disk_peak_state AggregateFunction(max, UInt8),
    total_cpu_state AggregateFunction(sum, Int64),
    cpu_peak_state AggregateFunction(max, UInt8),
    total_trate_state AggregateFunction(sum, Int64),
    total_erate_state AggregateFunction(sum, Int64),
    total_orate_state AggregateFunction(sum, Int64),
    lograte_peak_state AggregateFunction(max, Int64),
    totalsession_state AggregateFunction(sum, Int64),
    session_peak_state AggregateFunction(max, UInt32),
    total_setuprate_state AggregateFunction(sum, Int64),
    setuprate_peak_state AggregateFunction(max, Int64),
    sent_state AggregateFunction(sum, Int64),
    recv_state AggregateFunction(sum, Int64),
    count_state AggregateFunction(sum, Int64),
    transmit_peak_state AggregateFunction(max, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, slot, role, timescale)
ORDER BY (_adomoid, dvid, slot, role, timescale)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_resource_usage_hour_sp$SPID AS siem.fv_fgt_e_resource_usage_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_resource_usage_day_sp$SPID AS siem.fv_fgt_e_resource_usage_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_resource_usage_5min_mv_sp$SPID
TO siem.fv_fgt_e_resource_usage_5min_sp$SPID
AS SELECT 
    _adomoid,
    dvid,
    slot,
    cast(fgt_role, 'Nullable(String)') AS role,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    sumState(toInt64(total_mem)) AS total_mem_state,
    maxState(mem_peak) AS mem_peak_state,
    sumState(toInt64(total_disk)) AS total_disk_state,
    maxState(disk_peak) AS disk_peak_state,
    sumState(toInt64(total_cpu)) AS total_cpu_state,
    maxState(cpu_peak) AS cpu_peak_state,
    sumState(toInt64(total_trate)) AS total_trate_state,
    sumState(toInt64(total_erate)) AS total_erate_state,
    sumState(toInt64(total_orate)) AS total_orate_state,
    maxState(lograte_peak) AS lograte_peak_state,
    sumState(toInt64(_totalsession)) AS totalsession_state,
    maxState(session_peak) AS session_peak_state,
    sumState(toInt64(total_setuprate)) AS total_setuprate_state,
    maxState(toInt64(setuprate_peak)) AS setuprate_peak_state,
    sumState(toInt64(sent)) AS sent_state,
    sumState(toInt64(recv)) AS recv_state,
    sumState(toInt64(count)) AS count_state,
    maxState(transmit_peak) AS transmit_peak_state
FROM (
      SELECT
          _adomoid,
          dvid,
          itime AS timescale,
          $LOGFIELD-bandwidth-_bandwidth,
          $LOGFIELD-mem,
          $LOGFIELD-disk,
          $LOGFIELD-cpu,
          $LOGFIELD-trate,  
          $LOGFIELD-erate,  
          $LOGFIELD-orate,  
          $LOGFIELD-totalsession,
          $LOGFIELD-setuprate,
          $LOGFIELD-action,
          $LOGFIELD-slot,
          get_fgt_role(devid,slot) AS fgt_role,
          coalesce(_bandwidth,'0') AS bandwidth,
          coalesce(mem, 0) AS total_mem,
          coalesce(mem, 0) AS mem_peak,
          coalesce(disk, 0) AS total_disk,
          coalesce(disk, 0) AS disk_peak,
          coalesce(cpu, 0) AS total_cpu,
          coalesce(cpu, 0) AS cpu_peak,
          coalesce(trate, 0) AS total_trate,
          coalesce(erate, 0) AS total_erate,
          coalesce(orate, 0) AS total_orate,
          coalesce(trate, 0) + coalesce(erate, 0) + coalesce(orate, 0) AS lograte_peak,
          coalesce(totalsession, 0) AS _totalsession,
          coalesce(totalsession, 0) AS session_peak,
          coalesce(setuprate, 0) AS total_setuprate,
          coalesce(setuprate, 0) AS setuprate_peak,
          1 AS count,
          cast(coalesce(splitByChar('/', bandwidth)[1], '0') AS INT) AS sent,
          cast(coalesce(splitByChar('/', bandwidth)[2], '0') AS INT) AS recv,
          cast(coalesce(splitByChar('/', bandwidth)[1], '0') AS INT) + cast(coalesce(splitByChar('/', bandwidth)[2], '0') AS INT) AS transmit_peak
      FROM siem.elog_sp$SPID JOIN siem.devtable on siem.elog_sp$SPID.dvid = siem.devtable.dvid
      WHERE action = 'perf-stats' AND _devlogtype = 5
)
GROUP BY _adomoid, dvid, slot, role, timescale;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_resource_usage_hour_mv_sp$SPID
TO siem.fv_fgt_e_resource_usage_hour_sp$SPID
AS SELECT
    _adomoid,
    dvid,
    slot,
    role,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    sumState(total_mem) AS total_mem_state,
    maxState(mem_peak) AS mem_peak_state,
    sumState(total_disk) AS total_disk_state,
    maxState(disk_peak) AS disk_peak_state,
    sumState(total_cpu) AS total_cpu_state,
    maxState(cpu_peak) AS cpu_peak_state,
    sumState(total_trate) AS total_trate_state,
    sumState(total_erate) AS total_erate_state,
    sumState(total_orate) AS total_orate_state,
    maxState(lograte_peak) AS lograte_peak_state,
    sumState(totalsession) AS totalsession_state,
    maxState(session_peak) AS session_peak_state,
    sumState(total_setuprate) AS total_setuprate_state,
    maxState(setuprate_peak) AS setuprate_peak_state,
    sumState(sent) AS sent_state,
    sumState(recv) AS recv_state,
    sumState(count) AS count_state,
    maxState(transmit_peak) AS transmit_peak_state
FROM (
      SELECT
        _adomoid,
        dvid,
        slot,
        role,
        timescale,
        sumMerge(total_mem_state) AS total_mem,
        maxMerge(mem_peak_state) AS mem_peak,
        sumMerge(total_disk_state) AS total_disk,
        maxMerge(disk_peak_state) AS disk_peak,
        sumMerge(total_cpu_state) AS total_cpu,
        maxMerge(cpu_peak_state) AS cpu_peak,
        sumMerge(total_trate_state) AS total_trate,
        sumMerge(total_erate_state) AS total_erate,
        sumMerge(total_orate_state) AS total_orate,
        maxMerge(lograte_peak_state) AS lograte_peak,
        sumMerge(totalsession_state) AS totalsession,
        maxMerge(session_peak_state) AS session_peak,
        sumMerge(total_setuprate_state) AS total_setuprate,
        maxMerge(setuprate_peak_state) AS setuprate_peak,
        sumMerge(sent_state) AS sent,
        sumMerge(recv_state) AS recv,
        sumMerge(count_state) AS count,
        maxMerge(transmit_peak_state) AS transmit_peak
      FROM siem.fv_fgt_e_resource_usage_5min_sp$SPID
      GROUP BY _adomoid, dvid, slot, role, timescale
)
GROUP BY _adomoid, dvid, slot, role, timescale;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_resource_usage_day_mv_sp$SPID
TO siem.fv_fgt_e_resource_usage_day_sp$SPID
AS SELECT
    _adomoid,
    dvid,
    slot,
    role,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    sumState(total_mem) AS total_mem_state,
    maxState(mem_peak) AS mem_peak_state,
    sumState(total_disk) AS total_disk_state,
    maxState(disk_peak) AS disk_peak_state,
    sumState(total_cpu) AS total_cpu_state,
    maxState(cpu_peak) AS cpu_peak_state,
    sumState(total_trate) AS total_trate_state,
    sumState(total_erate) AS total_erate_state,
    sumState(total_orate) AS total_orate_state,
    maxState(lograte_peak) AS lograte_peak_state,
    sumState(totalsession) AS totalsession_state,
    maxState(session_peak) AS session_peak_state,
    sumState(total_setuprate) AS total_setuprate_state,
    maxState(setuprate_peak) AS setuprate_peak_state,
    sumState(sent) AS sent_state,
    sumState(recv) AS recv_state,
    sumState(count) AS count_state,
    maxState(transmit_peak) AS transmit_peak_state
FROM (
      SELECT
        _adomoid,
        dvid,
        slot,
        role,
        timescale,
        sumMerge(total_mem_state) AS total_mem,
        maxMerge(mem_peak_state) AS mem_peak,
        sumMerge(total_disk_state) AS total_disk,
        maxMerge(disk_peak_state) AS disk_peak,
        sumMerge(total_cpu_state) AS total_cpu,
        maxMerge(cpu_peak_state) AS cpu_peak,
        sumMerge(total_trate_state) AS total_trate,
        sumMerge(total_erate_state) AS total_erate,
        sumMerge(total_orate_state) AS total_orate,
        maxMerge(lograte_peak_state) AS lograte_peak,
        sumMerge(totalsession_state) AS totalsession,
        maxMerge(session_peak_state) AS session_peak,
        sumMerge(total_setuprate_state) AS total_setuprate,
        maxMerge(setuprate_peak_state) AS setuprate_peak,
        sumMerge(sent_state) AS sent,
        sumMerge(recv_state) AS recv,
        sumMerge(count_state) AS count,
        maxMerge(transmit_peak_state) AS transmit_peak
      FROM siem.fv_fgt_e_resource_usage_hour_sp$SPID
      GROUP BY _adomoid, dvid, slot, role, timescale
)
GROUP BY _adomoid, dvid, slot, role, timescale;

ALTER TABLE siem.fv_fgt_e_resource_usage_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
