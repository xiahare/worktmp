/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_e_sys_admin_event",
    "datasource_mv": "fv_fgt_e_sys_admin_event_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_e_sys_admin_event_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_sys_admin_event_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_sys_admin_event_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_sys_admin_event_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_sys_admin_event_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_e_sys_admin_event_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_sys_admin_event_5min_sp$SPID (
    _adomoid UInt64,
    dvid Int32,
    timescale DateTime,
    f_user Nullable(String),
    event_name Nullable(String),
    severity_fgt LowCardinality(Nullable(String)),
    severity LowCardinality(Nullable(String)),
    level LowCardinality(Nullable(String)),
    subtype LowCardinality(Nullable(String)),
    logid_state AggregateFunction(max, UInt64),
    count_state AggregateFunction(sum, Int64),
    login_num_state AggregateFunction(sum, Int64),
    login_fail_num_state AggregateFunction(sum, Int64),
    total_duration_state AggregateFunction(sum, Nullable(Int64)),
    total_change_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, f_user, event_name)
ORDER BY (_adomoid, dvid, timescale, f_user, event_name)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_sys_admin_event_hour_sp$SPID AS siem.fv_fgt_e_sys_admin_event_5min_sp$SPID;


CREATE TABLE IF NOT EXISTS siem.fv_fgt_e_sys_admin_event_day_sp$SPID AS siem.fv_fgt_e_sys_admin_event_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_sys_admin_event_5min_mv_sp$SPID
TO siem.fv_fgt_e_sys_admin_event_5min_sp$SPID
AS SELECT
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    f_user,
    event_name,
    severity_fgt,
    severity,
    level,
    subtype,
    maxState(logid_as_uint64) AS logid_state,
    sumState(toInt64(count)) AS count_state,
    sumState(toInt64(login_num)) AS login_num_state,
    sumState(toInt64(login_fail_num)) AS login_fail_num_state,
    sumState(toInt64(total_duration)) AS total_duration_state,
    sumState(toInt64(total_change)) AS total_change_state
FROM (
      SELECT
          _adomoid,
          dvid,
          _devlogtype,
          itime AS timescale,
          $LOGFIELD-user,
          $LOGFIELD-duration,
          nullif(user,'') AS f_user,
          $LOGFIELD-level,
          $LOGFIELD-logdesc,
          $LOGFIELD-msg,
          subtype,
          coalesce(nullifna(logdesc), msg) AS event_name,
           (CASE level
                WHEN 'emergency' THEN '4'
                WHEN 'alert' THEN '3'
                WHEN 'critical' THEN '2'
                WHEN 'error' THEN '1'
                ELSE '0'
            END) AS severity_fgt,
           (CASE
                WHEN level IN ('critical',
                               'alert',
                               'emergency') THEN '5'
                WHEN level='error' THEN '4'
                WHEN level='warning' THEN '3'
                WHEN level='notice' THEN '2'
                ELSE '1'
            END) AS severity,
           level,
           logid,
           logid_to_int(logid) AS logid_as_uint64,
          (CASE WHEN logid_as_uint64 = 32001 THEN 1 ELSE 0 END) AS login_num,
          (CASE WHEN logid_as_uint64 = 32002 THEN 1 ELSE 0 END) AS login_fail_num,
          (CASE WHEN logid_as_uint64 = 32003 THEN duration ELSE 0 END) AS total_duration,
          1 AS total_change,
          1 AS count
      FROM siem.elog_sp$SPID
      WHERE logid_as_uint64 IN (32001, 32002, 32003) AND user IS NOT NULL
            AND _devlogtype = 5
)
GROUP BY _adomoid, dvid, timescale, f_user, event_name, severity_fgt, severity, level, subtype;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_sys_admin_event_hour_mv_sp$SPID
TO siem.fv_fgt_e_sys_admin_event_hour_sp$SPID
AS SELECT
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    f_user,
    event_name,
    severity_fgt,
    severity,
    level,
    subtype,
    maxState(logid) AS logid_state,
    sumState(count) AS count_state,
    sumState(login_num) AS login_num_state,
    sumState(login_fail_num) AS login_fail_num_state,
    sumState(total_duration) AS total_duration_state,
    sumState(total_change) AS total_change_state
FROM (
      SELECT
          _adomoid,
          dvid,
          timescale,
          f_user,
          event_name,
          severity_fgt,
          severity,
          level,
          subtype,
          maxMerge(logid_state) AS logid,
          sumMerge(count_state) AS count,
          sumMerge(login_num_state) AS login_num,
          sumMerge(login_fail_num_state) AS login_fail_num,
          sumMerge(total_duration_state) AS total_duration,
          sumMerge(total_change_state) AS total_change
      FROM siem.fv_fgt_e_sys_admin_event_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale, f_user, event_name, severity_fgt, severity, level, subtype
)
GROUP BY _adomoid, dvid, timescale, f_user, event_name, severity_fgt, severity, level, subtype;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_e_sys_admin_event_day_mv_sp$SPID
TO siem.fv_fgt_e_sys_admin_event_day_sp$SPID
AS SELECT
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    f_user,
    event_name,
    severity_fgt,
    severity,
    level,
    subtype,
    maxState(logid) AS logid_state,
    sumState(count) AS count_state,
    sumState(login_num) AS login_num_state,
    sumState(login_fail_num) AS login_fail_num_state,
    sumState(total_duration) AS total_duration_state,
    sumState(total_change) AS total_change_state
FROM (
      SELECT
          _adomoid,
          dvid,
          timescale,
          f_user,
          event_name,
          severity_fgt,
          severity,
          level,
          subtype,
          maxMerge(logid_state) AS logid,
          sumMerge(count_state) AS count,
          sumMerge(login_num_state) AS login_num,
          sumMerge(login_fail_num_state) AS login_fail_num,
          sumMerge(total_duration_state) AS total_duration,
          sumMerge(total_change_state) AS total_change
      FROM siem.fv_fgt_e_sys_admin_event_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale, f_user, event_name, severity_fgt, severity, level, subtype
)
GROUP BY _adomoid, dvid, timescale, f_user, event_name, severity_fgt, severity, level, subtype;

ALTER TABLE siem.fv_fgt_e_sys_admin_event_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
