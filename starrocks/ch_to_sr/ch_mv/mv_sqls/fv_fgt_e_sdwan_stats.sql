/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_e_sdwan_stats",
    "datasource_mv": "fv_fgt_e_sdwan_stats_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_e_sdwan_stats_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_sdwan_stats_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_sdwan_stats_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_sdwan_stats_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_sdwan_stats_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_sdwan_stats_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_sdwan_stats_5min_sp$SPID (
    _adomoid UInt64,
    dvid Int32,
    timescale DateTime,
    interface Nullable(String),
    service LowCardinality(Nullable(String)),
    level LowCardinality(Nullable(String)),
    sla Nullable(String),
    moscodec Nullable(String),
    speedtestserver Nullable(String),
    mosvalue_state AggregateFunction(max, Float32),
    inbandwidth_state AggregateFunction(sum, Float64),
    outbandwidth_state AggregateFunction(sum, Float64),
    bibandwidth_state AggregateFunction(sum, Float64),
    upbandwidth_state AggregateFunction(sum, Float64),
    downbandwidth_state AggregateFunction(sum, Float64),
    latency_state AggregateFunction(sum, Float64),
    jitter_state AggregateFunction(sum, Float64),
    packetloss_state AggregateFunction(sum, Float64),
    max_sdwan_status_state AggregateFunction(max, Nullable(UInt8)),
    min_sdwan_status_state AggregateFunction(min, Nullable(UInt8)),
    count_linkup_state AggregateFunction(sum, Int64),
    count_slaup_state AggregateFunction(sum, Int64),
    speedtest_cnt_state AggregateFunction(sum, Int64),
    std_jitter_state AggregateFunction(stddevSamp, Float64),
    std_latency_state AggregateFunction(stddevSamp, Float64),
    std_packetloss_state AggregateFunction(stddevSamp, Float64),
    count_state AggregateFunction(sum, Int64) 
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, interface, service)
ORDER BY (_adomoid, dvid, timescale, interface, service, level, sla, moscodec)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_sdwan_stats_hour_sp$SPID AS siem.fv_fgt_e_sdwan_stats_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_sdwan_stats_day_sp$SPID AS siem.fv_fgt_e_sdwan_stats_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_sdwan_stats_5min_mv_sp$SPID
TO siem.fv_fgt_e_sdwan_stats_5min_sp$SPID
AS SELECT
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    service,
    interface,
    level,
    sla,
    moscodec,
    speedtestserver,
    maxState(mosvalue) AS mosvalue_state,
    sumState(inbandwidth) AS inbandwidth_state,
    sumState(outbandwidth) AS outbandwidth_state,
    sumState(bibandwidth) AS bibandwidth_state,
    sumState(upbandwidth) AS upbandwidth_state,
    sumState(downbandwidth) AS downbandwidth_state,
    sumState(toFloat64(latency)) AS latency_state,
    sumState(toFloat64(jitter)) AS jitter_state,
    sumState(toFloat64(packetloss)) AS packetloss_state,
    maxState(sdwan_status) AS max_sdwan_status_state,
    minState(sdwan_status) AS min_sdwan_status_state,
    sumState(toInt64(link_status)) AS count_linkup_state,
    sumState(toInt64(count_slaup)) AS count_slaup_state,
    sumState(toInt64(speedtest_cnt)) AS speedtest_cnt_state,
    stddevSampState(toFloat64(jitter/count)) AS std_jitter_state,
    stddevSampState(toFloat64(latency/count)) AS std_latency_state,
    stddevSampState(toFloat64(packetloss/count)) AS std_packetloss_state,
    sumState(toInt64(count)) AS count_state
FROM (
      SELECT
          _adomoid,
          dvid,
          _devlogtype,
          itime AS timescale,
          $LOGFIELD-interface,
          $LOGFIELD-service,
          $LOGFIELD-level,
          $LOGFIELD-healthcheck,
          $LOGFIELD-name,
          coalesce_str(healthcheck, name) AS sla,
          (CASE WHEN status='down' THEN 0 ELSE 1 END) AS link_status,
          coalesce(safeToFloat32($LOGFIELD_NOALIAS-latency),0) AS _latency,
          coalesce(safeToFloat32($LOGFIELD_NOALIAS-jitter),0) AS _jitter,
          coalesce(safeToFloat32(trim(TRAILING '%' FROM $LOGFIELD_NOALIAS-packetloss)),0) AS _packetloss,
          $LOGFIELD-moscodec,
          $LOGFIELD-speedtestserver,
          $LOGFIELD-mosvalue-_mosvalue,
          coalesce(safeToFloat32(_mosvalue),0) AS mosvalue,
          $LOGFIELD-status,
          $LOGFIELD-msg,  
          $LOGFIELD-inbandwidthused,
          $LOGFIELD-outbandwidthused,
          $LOGFIELD-bibandwidthused,
          $LOGFIELD-upbandwidthmeasured,
          $LOGFIELD-downbandwidthmeasured,
          coalesce(convert_unit_to_number(inbandwidthused),0) as _inbandwidth,
          coalesce(convert_unit_to_number(outbandwidthused),0) as _outbandwidth,
          coalesce(convert_unit_to_number(bibandwidthused),0) as _bibandwidth,
          coalesce(convert_unit_to_number(upbandwidthmeasured),0) as _upbandwidth,
          coalesce(convert_unit_to_number(downbandwidthmeasured),0) as _downbandwidth,
          (CASE WHEN status='down' THEN 1 WHEN msg LIKE '%failed due to%' THEN 1 ELSE 0 END) AS sla_failed,
          (CASE WHEN msg LIKE '%SLA status%' OR status='up' THEN 1 WHEN status='down' THEN 3 ELSE NULL END) AS _sdwan_status,
          (CASE WHEN link_status=1 THEN _inbandwidth ELSE 0 END) as inbandwidth,
          (CASE WHEN link_status=1 THEN _outbandwidth ELSE 0 END) as outbandwidth,
          (CASE WHEN link_status=1 THEN _bibandwidth ELSE 0 END) as bibandwidth,
          (CASE WHEN link_status=1 THEN _upbandwidth ELSE 0 END) as upbandwidth,
          (CASE WHEN link_status=1 THEN _downbandwidth ELSE 0 END) as downbandwidth,
          (CASE WHEN link_status=1 THEN _latency ELSE 0 END) AS latency,
          (CASE WHEN link_status=1 THEN _jitter ELSE 0 END) AS jitter,
          (CASE WHEN link_status=1 THEN _packetloss ELSE 100 END) AS packetloss,
          (CASE WHEN sla_failed=1 THEN 3 ELSE _sdwan_status END) AS sdwan_status,
          (CASE WHEN sla_failed=1 THEN 0 ELSE 1 END) as count_slaup,
          (CASE WHEN logid_to_int(logid)=22938 THEN 1 ELSE 0 END) AS speedtest_cnt,
          logid_to_int(logid) AS logid_as_uint64,
          1 AS count
      FROM siem.elog_sp$SPID
      WHERE logid_as_uint64 IN (22925, 22933, 22936, 22938) AND interface IS NOT NULL
            AND _devlogtype = 5
)
GROUP BY _adomoid, dvid, timescale, interface, service, level, sla, moscodec, speedtestserver;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_sdwan_stats_hour_mv_sp$SPID
TO siem.fv_fgt_e_sdwan_stats_hour_sp$SPID
AS SELECT
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    service,
    interface,
    level,
    sla,
    moscodec,
    speedtestserver,
    maxState(mosvalue) AS mosvalue_state,
    sumState(inbandwidth) AS inbandwidth_state,
    sumState(outbandwidth) AS outbandwidth_state,
    sumState(bibandwidth) AS bibandwidth_state,
    sumState(upbandwidth) AS upbandwidth_state,
    sumState(downbandwidth) AS downbandwidth_state,
    sumState(latency) AS latency_state,
    sumState(jitter) AS jitter_state,
    sumState(packetloss) AS packetloss_state,
    maxState(max_sdwan_status) AS max_sdwan_status_state,
    minState(min_sdwan_status) AS min_sdwan_status_state,
    sumState(count_linkup) AS count_linkup_state,
    sumState(count_slaup) AS count_slaup_state,
    sumState(speedtest_cnt) AS speedtest_cnt_state,
    stddevSampState(toFloat64(jitter/count)) AS std_jitter_state,
    stddevSampState(toFloat64(latency/count)) AS std_latency_state,
    stddevSampState(toFloat64(packetloss/count)) AS std_packetloss_state,
    sumState(count) AS count_state
FROM (
      SELECT
          _adomoid,
          dvid,
          timescale,
          service,
          interface,
          level,
          sla,
          moscodec,
          speedtestserver,
          maxMerge(mosvalue_state) AS mosvalue,
          sumMerge(inbandwidth_state) AS inbandwidth,
          sumMerge(outbandwidth_state) AS outbandwidth,
          sumMerge(bibandwidth_state) AS bibandwidth,
          sumMerge(upbandwidth_state) AS upbandwidth,
          sumMerge(downbandwidth_state) AS downbandwidth,
          sumMerge(latency_state) AS latency,
          sumMerge(jitter_state) AS jitter,
          sumMerge(packetloss_state) AS packetloss,
          maxMerge(max_sdwan_status_state) AS max_sdwan_status,
          minMerge(min_sdwan_status_state) AS min_sdwan_status,
          sumMerge(count_linkup_state) AS count_linkup,
          sumMerge(count_slaup_state) AS count_slaup,
          sumMerge(speedtest_cnt_state) AS speedtest_cnt,
          sumMerge(count_state) AS count
      FROM siem.fv_fgt_e_sdwan_stats_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale, interface, service, level, sla, moscodec, speedtestserver
)
GROUP BY _adomoid, dvid, timescale, interface, service, level, sla, moscodec, speedtestserver;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_sdwan_stats_day_mv_sp$SPID
TO siem.fv_fgt_e_sdwan_stats_day_sp$SPID
AS SELECT
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    service,
    interface,
    level,
    sla,
    moscodec,
    speedtestserver,
    maxState(mosvalue) AS mosvalue_state,
    sumState(inbandwidth) AS inbandwidth_state,
    sumState(outbandwidth) AS outbandwidth_state,
    sumState(bibandwidth) AS bibandwidth_state,
    sumState(upbandwidth) AS upbandwidth_state,
    sumState(downbandwidth) AS downbandwidth_state,
    sumState(latency) AS latency_state,
    sumState(jitter) AS jitter_state,
    sumState(packetloss) AS packetloss_state,
    maxState(max_sdwan_status) AS max_sdwan_status_state,
    minState(min_sdwan_status) AS min_sdwan_status_state,
    sumState(count_linkup) AS count_linkup_state,
    sumState(count_slaup) AS count_slaup_state,
    sumState(speedtest_cnt) AS speedtest_cnt_state,
    stddevSampState(toFloat64(jitter/count)) AS std_jitter_state,
    stddevSampState(toFloat64(latency/count)) AS std_latency_state,
    stddevSampState(toFloat64(packetloss/count)) AS std_packetloss_state,
    sumState(count) AS count_state
FROM (
      SELECT
          _adomoid,
          dvid,
          timescale,
          service,
          interface,
          level,
          sla,
          moscodec,
          speedtestserver,
          maxMerge(mosvalue_state) AS mosvalue,
          sumMerge(inbandwidth_state) AS inbandwidth,
          sumMerge(outbandwidth_state) AS outbandwidth,
          sumMerge(bibandwidth_state) AS bibandwidth,
          sumMerge(upbandwidth_state) AS upbandwidth,
          sumMerge(downbandwidth_state) AS downbandwidth,
          sumMerge(latency_state) AS latency,
          sumMerge(jitter_state) AS jitter,
          sumMerge(packetloss_state) AS packetloss,
          maxMerge(max_sdwan_status_state) AS max_sdwan_status,
          minMerge(min_sdwan_status_state) AS min_sdwan_status,
          sumMerge(count_linkup_state) AS count_linkup,
          sumMerge(count_slaup_state) AS count_slaup,
          sumMerge(speedtest_cnt_state) AS speedtest_cnt,
          sumMerge(count_state) AS count
      FROM siem.fv_fgt_e_sdwan_stats_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale, interface, service, level, sla, moscodec, speedtestserver
)
GROUP BY _adomoid, dvid, timescale, interface, service, level, sla, moscodec, speedtestserver;

ALTER TABLE siem.fv_fgt_e_sdwan_stats_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
