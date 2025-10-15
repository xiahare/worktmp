/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_r_si_cloud_app",
    "datasource_mv": "fv_fgt_r_si_cloud_app_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_r_si_cloud_app_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_r_si_cloud_app_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_r_si_cloud_app_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_r_si_cloud_app_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_r_si_cloud_app_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_r_si_cloud_app_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_r_si_cloud_app_5min_sp$SPID (
       timescale DateTime,
       dvid Int32,
       _adomoid UInt64,
       application Nullable(String),
       clouduser Nullable(String),
       category Nullable(String),
       risk LowCardinality(Nullable(String)),
       risk_enum Int8,
       app_group Nullable(String),
       f_user Nullable(String),
       srcip Nullable(IPv6),
       srcintf LowCardinality(Nullable(String)),
       srcintfrole LowCardinality(Nullable(String)),
       dstip Nullable(IPv6),
       dstintf LowCardinality(Nullable(String)),
       dstintfrole LowCardinality(Nullable(String)),
       dstcountry Nullable(String),
       filename Nullable(String),
       profile Nullable(String),
       service LowCardinality(Nullable(String)),
       siappid Nullable(UInt32),
       siflags Nullable(UInt32),
       policymode LowCardinality(Nullable(String)),
       policyid Nullable(UInt32),
       policytype LowCardinality(Nullable(String)),
       poluuid Nullable(UUID),
       files_state AggregateFunction(groupArray, Nullable(String)),
       sihash Nullable(Int64),
       upload_files_state AggregateFunction(sum, Int64),
       download_files_state AggregateFunction(sum, Int64),
       video_files_state AggregateFunction(sum, Int64),
       total_size_state AggregateFunction(sum, Int64),
       upload_size_state AggregateFunction(sum, Int64),
       download_size_state AggregateFunction(sum, Int64),
       session_block_state AggregateFunction(sum, Int64),
       sessions_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, application, clouduser, category)
ORDER BY (_adomoid, dvid, timescale,
          application, clouduser, category, risk, risk_enum, app_group,
          f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole, dstcountry, filename, profile, service, siappid, siflags,
          policymode, policytype, policyid, poluuid)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;


CREATE TABLE IF NOT EXISTS siem.fv_fgt_r_si_cloud_app_hour_sp$SPID AS siem.fv_fgt_r_si_cloud_app_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_r_si_cloud_app_day_sp$SPID AS siem.fv_fgt_r_si_cloud_app_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_r_si_cloud_app_5min_mv_sp$SPID
TO siem.fv_fgt_r_si_cloud_app_5min_sp$SPID
AS SELECT 
       fv_timescale_func(timescale, 300, 0) AS timescale,
       dvid,
       _adomoid,
       application,
       clouduser,
       category,
       risk,
       risk_enum, siappid, siflags,
       app_group,
       f_user,
       srcip,
       srcintf,
       srcintfrole,
       dstip,
       dstintf,
       dstintfrole,
       dstcountry,
       file_name as filename,
       profile,
       service,
       groupArrayState(file_name) AS files_state,
       sihash,
       policymode,
       policyid,
       policytype,
       poluuid,
       sumState(toInt64(upload_files)) AS upload_files_state,
       sumState(toInt64(download_files)) AS download_files_state,
       sumState(toInt64(video_files)) AS video_files_state,
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
           appname as application,
           riskscore,
           app_group_name(app) as app_group,
           clouduser,
           $LOGFIELD-cloudaction,
           $LOGFIELD-action,
           $LOGFIELD-filename,
           $LOGFIELD-filesize,
           $LOGFIELD-user, 
           $LOGFIELD-unauthuser,
           $LOGFIELD-srcip,
           $LOGFIELD-srcintf,
           $LOGFIELD-srcintfrole,
           $LOGFIELD-dstip,
           $LOGFIELD-dstintf,
           $LOGFIELD-dstintfrole,
           $LOGFIELD-dstcountry,
           $LOGFIELD-profile,
           $LOGFIELD-service,
           $LOGFIELD-siflags,
           $LOGFIELD-siappid,
           $LOGFIELD-policymode,
           $LOGFIELD-policyid,
           $LOGFIELD-policytype,
           $LOGFIELD-poluuid,
           JSONExtractString(attributes, 'Information', 'Category') AS category ,
           (CASE WHEN cloudaction='upload' THEN 1 WHEN cloudaction='download' THEN 2 WHEN cloudaction='others' AND app LIKE '%Video%' THEN 3 ELSE 0 END) AS flags,
           (CASE WHEN action NOT IN ('pass', 'monitor') THEN 1 ELSE 0 END) AS session_block,
           nullif(filename,'') as file_name,
           filesize,
           coalesce(nullifna(`user`), nullifna(`unauthuser`)) AS f_user,
           (case when riskscore BETWEEN 0 AND 19 then 'Low' when riskscore BETWEEN 20 AND 39 then 'Elevated' when riskscore BETWEEN 40 AND 59 then 'Medium' when riskscore BETWEEN 60 AND 79 then 'High' when riskscore BETWEEN 80 AND 100 then 'Critical' else 'N/A' end) as risk,
           (case when riskscore BETWEEN 0 AND 19 then 1 when riskscore BETWEEN 20 AND 39 then 2 when riskscore BETWEEN 40 AND 59 then 3 when riskscore BETWEEN 60 AND 79 then 4 when riskscore BETWEEN 80 AND 100 then 5 else 0 end) as risk_enum,
           (CASE WHEN flags=1 THEN 1 ELSE 0 END) AS upload_files,
           (CASE WHEN flags=2 THEN 1 ELSE 0 END) AS download_files,
           (CASE WHEN flags=3 THEN 1 ELSE 0 END) AS video_files,
           $LOGFIELD-sihash,
           (coalesce(filesize, 0)) AS total_size,
           (CASE WHEN flags=1 THEN coalesce(filesize, 0) ELSE 0 END) AS upload_size,
           (CASE WHEN flags in (2,3) THEN coalesce(filesize, 0) ELSE 0 END) AS download_size,
           1 AS sessions
           FROM siem.ulog_sp$SPID ac
           LEFT JOIN siem.shadowit_application sa
           ON siappid = sa.appid
           WHERE _devlogtype = 0 AND appname IS NOT NULL AND NOT (bitAnd(siflags,1) > 0) AND siappid is not null
)
GROUP BY _adomoid, dvid, timescale,
          application, clouduser, category, risk, risk_enum, app_group,
          f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole, dstcountry, file_name, profile, service, siappid, sihash, siflags,
          policymode, policytype, policyid, poluuid;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_r_si_cloud_app_hour_mv_sp$SPID
TO siem.fv_fgt_r_si_cloud_app_hour_sp$SPID
AS SELECT
       fv_timescale_func(timescale, 3600, 0) AS timescale,
       dvid,
       _adomoid,
       application, clouduser, category,
       risk,
       risk_enum,
       siappid,
       siflags,
       app_group,
       f_user,
       srcip,
       srcintf,
       srcintfrole,
       dstip,
       dstintf,
       dstintfrole,
       dstcountry,
       filename,
       profile,
       service,
       sihash,
       policymode,
       policyid,
       policytype,
       poluuid,
       sumState(upload_files) AS upload_files_state,
       sumState(download_files) AS download_files_state,
       sumState(video_files) AS video_files_state,
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
       application, clouduser, category,
       risk,
       risk_enum,
       siappid,
       siflags,
       app_group,
       f_user,
       srcip,
       srcintf,
       srcintfrole,
       dstip,
       dstintf,
       dstintfrole,
       dstcountry,
       filename,
       profile,
       service,
       sihash,
       policymode,
       policyid,
       policytype,
       poluuid,
       sumMerge(upload_files_state) AS upload_files,
       sumMerge(download_files_state) AS download_files,
       sumMerge(video_files_state) AS video_files,
       sumMerge(total_size_state) AS total_size,
       sumMerge(upload_size_state) AS upload_size,
       sumMerge(download_size_state) AS download_size,
       sumMerge(session_block_state) AS session_block,
       sumMerge(sessions_state) AS sessions
    FROM siem.fv_fgt_r_si_cloud_app_5min_sp$SPID
    GROUP BY _adomoid, dvid, timescale,
             application, clouduser, category, risk, risk_enum, app_group,
             f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole, dstcountry, filename, profile, service, siappid, sihash, siflags,
             policymode, policytype, policyid, poluuid
)
GROUP BY _adomoid, dvid, timescale,
          application, clouduser, category, risk, risk_enum, app_group,
          f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole, dstcountry, filename, profile, service, siappid, sihash, siflags,
          policymode, policytype, policyid, poluuid;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_r_si_cloud_app_day_mv_sp$SPID
TO siem.fv_fgt_r_si_cloud_app_day_sp$SPID
AS SELECT
       fv_timescale_func(timescale, 28800, 0) AS timescale,
       dvid,
       _adomoid,
       application, clouduser, category,
       risk,
       risk_enum,
       siappid,
       siflags,
       app_group,
       f_user,
       srcip,
       srcintf,
       srcintfrole,
       dstip,
       dstintf,
       dstintfrole,
       dstcountry,
       filename,
       profile,
       service,
       sihash,
       policymode,
       policyid,
       policytype,
       poluuid,
       sumState(upload_files) AS upload_files_state,
       sumState(download_files) AS download_files_state,
       sumState(video_files) AS video_files_state,
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
       application, clouduser, category,
       risk,
       risk_enum,
       siappid,
       siflags,
       app_group,
       f_user,
       srcip,
       srcintf,
       srcintfrole,
       dstip,
       dstintf,
       dstintfrole,
       dstcountry,
       filename,
       profile,
       service,
       sihash,
       policymode,
       policyid,
       policytype,
       poluuid,
       sumMerge(upload_files_state) AS upload_files,
       sumMerge(download_files_state) AS download_files,
       sumMerge(video_files_state) AS video_files,
       sumMerge(total_size_state) AS total_size,
       sumMerge(upload_size_state) AS upload_size,
       sumMerge(download_size_state) AS download_size,
       sumMerge(session_block_state) AS session_block,
       sumMerge(sessions_state) AS sessions
    FROM siem.fv_fgt_r_si_cloud_app_hour_sp$SPID
    GROUP BY _adomoid, dvid, timescale,
             application, clouduser, category, risk, risk_enum, app_group,
             f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole, dstcountry, filename, profile, service, siappid, sihash, siflags,
             policymode, policytype, policyid, poluuid
)
GROUP BY _adomoid, dvid, timescale,
          application, clouduser, category, risk, risk_enum, app_group,
          f_user, srcip, srcintf, srcintfrole, dstip, dstintf, dstintfrole, dstcountry, filename, profile, service, siappid, sihash, siflags,
          policymode, policytype, policyid, poluuid;

ALTER TABLE siem.fv_fgt_r_si_cloud_app_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
