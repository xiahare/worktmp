/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fpx_r_si_cloud_app",
    "datasource_mv": "fv_fpx_r_si_cloud_app_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fpx_r_si_cloud_app_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fpx_r_si_cloud_app_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fpx_r_si_cloud_app_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fpx_r_si_cloud_app_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fpx_r_si_cloud_app_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fpx_r_si_cloud_app_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fpx_r_si_cloud_app_5min_sp$SPID (
       timescale DateTime,
       dvid Int32,
       _adomoid UInt64,
       clouduser Nullable(String),
       app_group Nullable(String),
       f_user Nullable(String),
       srcip Nullable(IPv6),
       dstcountry Nullable(String),
       filename Nullable(String),
       profile Nullable(String),
       service LowCardinality(Nullable(String)),
       upload_files_state AggregateFunction(sum, Int64),
       download_files_state AggregateFunction(sum, Int64),
       video_files_state AggregateFunction(sum, Int64),
       files_state AggregateFunction(groupArray, Nullable(String)),
       total_size_state AggregateFunction(sum, Int64),
       upload_size_state AggregateFunction(sum, Int64),
       download_size_state AggregateFunction(sum, Int64),
       session_block_state AggregateFunction(sum, Int64),
       sessions_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, clouduser)
ORDER BY (_adomoid, dvid, timescale,
          clouduser, app_group,
          f_user, srcip, dstcountry, filename, profile, service)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;


CREATE TABLE IF NOT EXISTS siem.fv_fpx_r_si_cloud_app_hour_sp$SPID AS siem.fv_fpx_r_si_cloud_app_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fpx_r_si_cloud_app_day_sp$SPID AS siem.fv_fpx_r_si_cloud_app_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fpx_r_si_cloud_app_5min_mv_sp$SPID
TO siem.fv_fpx_r_si_cloud_app_5min_sp$SPID
AS SELECT
       fv_timescale_func(timescale, 300, 0) AS timescale,
       dvid,
       _adomoid,
       clouduser,
       app_group, f_user, srcip, dstcountry, filename, profile, service,
       sumState(toInt64(upload_files)) AS upload_files_state,
       sumState(toInt64(download_files)) AS download_files_state,
       sumState(toInt64(video_files)) AS video_files_state,
       groupArrayState(files) AS files_state,
       sumState(toInt64(total_size)) AS total_size_state,
       sumState(toInt64(upload_size)) AS upload_size_state,
       sumState(toInt64(download_size)) AS download_size_state,
       sumState(toInt64(session_block)) AS session_block_state,
       sumState(toInt64(sessions)) AS sessions_state
    FROM (
       SELECT
           itime as timescale,
           dvid,
           _adomoid,
           $LOGFIELD-app,
           $LOGFIELD-clouduser,
           app_group_name(app) as app_group,
           clouduser,
           $LOGFIELD-cloudaction,
           $LOGFIELD-action,
           $LOGFIELD-filename,
           $LOGFIELD-filesize,
           $LOGFIELD-user,
           $LOGFIELD-unauthuser,
           $LOGFIELD-srcip,
           $LOGFIELD-dstcountry,
           $LOGFIELD-profile,
           $LOGFIELD-service,
           (CASE WHEN cloudaction='upload' THEN 1 WHEN cloudaction='download' THEN 2 WHEN cloudaction='others' AND app LIKE '%Video%' THEN 3 ELSE 0 END) AS flags,
           (CASE WHEN action NOT IN ('pass', 'monitor') THEN 1 ELSE 0 END) AS session_block,
           filename,
           filesize,
           coalesce(nullifna(`user`), nullifna(`unauthuser`)) AS f_user,
           (CASE WHEN flags=1 THEN 1 ELSE 0 END) AS upload_files,
           (CASE WHEN flags=2 THEN 1 ELSE 0 END) AS download_files,
           (CASE WHEN flags=3 THEN 1 ELSE 0 END) AS video_files,
           $LOGFIELD-filename,
           nullif(filename,'') AS files,
           (coalesce(filesize, 0)) AS total_size,
           (CASE WHEN flags=1 THEN coalesce(filesize, 0) ELSE 0 END) AS upload_size,
           (CASE WHEN flags in (2,3) THEN coalesce(filesize, 0) ELSE 0 END) AS download_size,
           1 AS sessions
           FROM siem.ulog_sp$SPID ac
           WHERE _devlogtype = 15000 AND bitAnd(logflag, 4) >0
)
GROUP BY _adomoid, dvid, timescale,
          clouduser, app_group,
          f_user, srcip, dstcountry, filename, profile, service;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fpx_r_si_cloud_app_hour_mv_sp$SPID
TO siem.fv_fpx_r_si_cloud_app_hour_sp$SPID
AS SELECT
       fv_timescale_func(timescale, 3600, 0) AS timescale,
       dvid,
       _adomoid,
       clouduser,
       app_group, f_user, srcip, dstcountry, filename, profile, service,
       sumState(upload_files) AS upload_files_state,
       sumState(download_files) AS download_files_state,
       sumState(video_files) AS video_files_state,
       groupArrayMergeState(files) AS files_state,
       sumState(total_size) AS total_size_state,
       sumState(upload_size) AS upload_size_state,
       sumState(download_size) AS download_size_state,
       sumState(session_block) AS session_block_state,
       sumState(sessions) AS sessions_state
FROM (
    SELECT
       timescale,
       dvid,
       _adomoid,
       clouduser,
       app_group, f_user, srcip, dstcountry, filename, profile, service,
       sumMerge(upload_files_state) AS upload_files,
       sumMerge(download_files_state) AS download_files,
       sumMerge(video_files_state) AS video_files,
       groupArrayMergeState(files_state) AS files,
       sumMerge(total_size_state) AS total_size,
       sumMerge(upload_size_state) AS upload_size,
       sumMerge(download_size_state) AS download_size,
       sumMerge(session_block_state) AS session_block,
       sumMerge(sessions_state) AS sessions
    FROM siem.fv_fpx_r_si_cloud_app_5min_sp$SPID
    GROUP BY _adomoid, dvid, timescale,
             clouduser, app_group,
             f_user, srcip, dstcountry, filename, profile, service
)
GROUP BY _adomoid, dvid, timescale,
          clouduser, app_group,
          f_user, srcip, dstcountry, filename, profile, service;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fpx_r_si_cloud_app_day_mv_sp$SPID
TO siem.fv_fpx_r_si_cloud_app_day_sp$SPID
AS SELECT
       fv_timescale_func(timescale, 28800, 0) AS timescale,
       dvid,
       _adomoid,
       clouduser,
       app_group, f_user, srcip, dstcountry, filename, profile, service,
       sumState(upload_files) AS upload_files_state,
       sumState(download_files) AS download_files_state,
       sumState(video_files) AS video_files_state,
       groupArrayMergeState(files) AS files_state,
       sumState(total_size) AS total_size_state,
       sumState(upload_size) AS upload_size_state,
       sumState(download_size) AS download_size_state,
       sumState(session_block) AS session_block_state,
       sumState(sessions) AS sessions_state
FROM (
    SELECT
       timescale,
       dvid,
       _adomoid,
       clouduser,
       app_group, f_user, srcip, dstcountry, filename, profile, service,
       sumMerge(upload_files_state) AS upload_files,
       sumMerge(download_files_state) AS download_files,
       sumMerge(video_files_state) AS video_files,
       groupArrayMergeState(files_state) AS files,
       sumMerge(total_size_state) AS total_size,
       sumMerge(upload_size_state) AS upload_size,
       sumMerge(download_size_state) AS download_size,
       sumMerge(session_block_state) AS session_block,
       sumMerge(sessions_state) AS sessions
    FROM siem.fv_fpx_r_si_cloud_app_hour_sp$SPID
    GROUP BY _adomoid, dvid, timescale,
             clouduser, app_group,
             f_user, srcip, dstcountry, filename, profile, service
)
GROUP BY _adomoid, dvid, timescale,
          clouduser, app_group,
          f_user, srcip, dstcountry, filename, profile, service;

ALTER TABLE siem.fv_fpx_r_si_cloud_app_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
