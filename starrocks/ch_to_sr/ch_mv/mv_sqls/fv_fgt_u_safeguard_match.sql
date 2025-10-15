/*
{
    "type": "sp_mv",
    "version": "070600.3361",
    "name": "fv_fgt_u_safeguard_match",
    "datasource_mv": "fv_fgt_u_safeguard_match_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_u_safeguard_match_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_u_safeguard_match_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_u_safeguard_match_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_u_safeguard_match_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_u_safeguard_match_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_u_safeguard_match_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_u_safeguard_match_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_u_safeguard_match_day_sp$SPID;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_u_safeguard_match_sp$SPID (
    _adomoid UInt64,
    dvid Int32,
    itime DateTime,
    loguid UInt64,
    devlogtype Int32,
    epid Int32,
    euid Int32,
    dstepid Int32,
    dsteuid Int32,
    srcip Nullable(IPv6),
    dstip Nullable(IPv6),
    app LowCardinality(Nullable(String)),
    avatar Nullable(String),
    f_user Nullable(String),
    keywords String,
    category LowCardinality(String),
    host_name Nullable(String),
    inspected_data String
)
ENGINE = AggregatingMergeTree()
ORDER BY (_adomoid, itime, euid, dvid)
PARTITION BY toYYYYMMDD(itime)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_u_safeguard_match_mv_sp$SPID
TO siem.fv_fgt_u_safeguard_match_sp$SPID
AS SELECT _adomoid, dvid, itime,
       loguid,
       devlogtype,
       epid,
       euid,
       dstepid,
       dsteuid,
       srcip,
       dstip,
       application as app,
       f_user,
       avatar,
       JSONExtractString(match_result, 'keywords') as keywords,
       JSONExtractString(match_result, 'category') as category,
       host_name,
       inspected_data
       FROM (
           SELECT
               itime,
               dvid,
               _adomoid,
               _devlogtype AS devlogtype,
               $LOGFIELD-fgt-r-epid,
               $LOGFIELD-fgt-r-euid,
               $LOGFIELD-fgt-r-dstepid,
               $LOGFIELD-fgt-r-dsteuid,
               $LOGFIELD-fgt-r-dstip,
               $LOGFIELD-fgt-r-srcip,
               $LOGFIELD-fgt-r-loguid,
               $LOGFIELD-fgt-r-user,
               $LOGFIELD-fgt-r-unauthuser,
               $LOGFIELD-fgt-r-app,
               $LOGFIELD-fgt-r-service,
               $LOGFIELD-fgt-r-filename,
               $LOGFIELD-fgt-r-hostname,
               $LOGFIELD-fgt-w-keyword,
               $LOGFIELD-fgt-s-subject,
               $LOGFIELD-fgt-r-fctuid,
               (CASE WHEN fctuid IS NOT NULL AND unauthuser IS NOT NULL THEN CONCAT(toString(fctuid), ',', unauthuser) ELSE NULL END) AS avatar,
               coalesce(nullifna(user), nullifna(unauthuser), ipstr(srcip)) AS f_user,
               multiIf(_devlogtype = 0, app, service) as application,
               multiIf(_devlogtype = 0 OR _devlogtype = 13, hostname, NULL) as host_name,
               multiIf(_devlogtype = 0, filename, _devlogtype = 13, keyword, _devlogtype = 4, subject, '') AS inspected_data,
               safeguardMatchDetail(multiIf(_devlogtype = 0, filename, _devlogtype = 13, keyword, _devlogtype = 4, subject, '')) AS match_result
          FROM siem.ulog_sp$SPID
          WHERE ((_devlogtype = 0 AND filename IS NOT NULL) or (_devlogtype = 13 AND keyword IS NOT NULL) or (_devlogtype = 4 AND subject IS NOT NULL)) and not empty(match_result)
);

CREATE TABLE IF NOT EXISTS siem.fv_fgt_u_safeguard_match_5min_sp$SPID (
    _adomoid UInt64,
    dvid Int32,
    timescale DateTime,
    devlogtype Int32,
    epid Int32,
    euid Int32,
    dstepid Int32,
    dsteuid Int32,
    srcip Nullable(IPv6),
    dstip Nullable(IPv6),
    app LowCardinality(Nullable(String)),
    f_user Nullable(String),
    keywords String,
    category LowCardinality(String),
    host_name Nullable(String),
    avatar_state  AggregateFunction(max, Nullable(String)),
    inspected_data_state AggregateFunction(groupUniqArray(10), String),
    match_state AggregateFunction(safeguardMatch, String, Float64),
    loguids_state AggregateFunction(groupArray(100), UInt64),
    count_state AggregateFunction(sum, UInt64),
    min_itime_state AggregateFunction(min, DateTime),
    max_itime_state AggregateFunction(max, DateTime)
)
ENGINE = AggregatingMergeTree()
ORDER BY (_adomoid, dvid, timescale,
         devlogtype, epid, euid, dstepid, dsteuid, dstip, srcip, app, f_user, keywords, category, host_name)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_u_safeguard_match_hour_sp$SPID AS siem.fv_fgt_u_safeguard_match_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_u_safeguard_match_day_sp$SPID AS siem.fv_fgt_u_safeguard_match_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_u_safeguard_match_5min_mv_sp$SPID
TO siem.fv_fgt_u_safeguard_match_5min_sp$SPID
AS SELECT _adomoid, dvid, fv_timescale_func(itime, 300, 0) AS timescale,
       devlogtype,
       epid,
       euid,
       dstepid,
       dsteuid,
       dstip,
       srcip,
       app,
       f_user,
       keywords,
       category,
       host_name,
       maxState(avatar) AS avatar_state,
       groupUniqArrayState(10)(inspected_data) AS inspected_data_state,
       safeguardMatchState(keywords, 0.5) AS match_state,
       sumState(toUInt64(1)) AS count_state,
       minState(itime) AS min_itime_state,
       maxState(itime) AS max_itime_state,
       groupArrayState(100)(loguid) AS loguids_state
       FROM siem.fv_fgt_u_safeguard_match_sp$SPID
GROUP BY _adomoid, dvid, timescale,
         devlogtype, epid, euid, dstepid, dsteuid, dstip, srcip, app, f_user, keywords, category, host_name;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_u_safeguard_match_hour_mv_sp$SPID
TO siem.fv_fgt_u_safeguard_match_hour_sp$SPID
AS SELECT _adomoid, dvid, fv_timescale_func(timescale, 3600, 0) AS timescale,
       devlogtype,
       epid,
       euid,
       dstepid,
       dsteuid,
       dstip,
       srcip,
       app,
       f_user,
       keywords,
       category,
       host_name,
       maxState(avatar) AS avatar_state,
       groupUniqArrayStateArray(10)(inspected_data) AS inspected_data_state,
       safeguardMatchMergeState(match) AS match_state,
       sumState(count) AS count_state,
       minState(min_itime) AS min_itime_state,
       maxState(max_itime) AS max_itime_state,
       groupArrayStateArray(100)(loguids) AS loguids_state
       FROM (
           SELECT
               _adomoid,
               dvid,
               timescale,
               devlogtype,
               epid,
               euid,
               dstepid,
               dsteuid,
               dstip,
               srcip,
               app,
               f_user,
               keywords,
               category,
               host_name,
               maxMerge(avatar_state) AS avatar,
               groupUniqArrayMerge(10)(inspected_data_state) AS inspected_data,
               safeguardMatchMergeState(match_state) AS match,
               sumMerge(count_state) AS count,
               minMerge(min_itime_state) AS min_itime,
               maxMerge(max_itime_state) AS max_itime,
               groupArrayMerge(100)(loguids_state) AS loguids
          FROM siem.fv_fgt_u_safeguard_match_5min_sp$SPID
          GROUP BY _adomoid, dvid, timescale,
                   devlogtype, epid, euid, dstepid, dsteuid, dstip, srcip, app, f_user, keywords, category, host_name
)
GROUP BY _adomoid, dvid, timescale,
         devlogtype, epid, euid, dstepid, dsteuid, dstip, srcip, app, f_user, keywords, category, host_name;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_u_safeguard_match_day_mv_sp$SPID
TO siem.fv_fgt_u_safeguard_match_day_sp$SPID
AS SELECT _adomoid, dvid, fv_timescale_func(timescale, 28800, 0) AS timescale,
       devlogtype,
       epid,
       euid,
       dstepid,
       dsteuid,
       dstip,
       srcip,
       app,
       f_user,
       keywords,
       category,
       host_name,
       maxState(avatar) AS avatar_state,
       groupUniqArrayStateArray(10)(inspected_data) AS inspected_data_state,
       safeguardMatchMergeState(match) AS match_state,
       sumState(count) AS count_state,
       minState(min_itime) AS min_itime_state,
       maxState(max_itime) AS max_itime_state,
       groupArrayStateArray(100)(loguids) AS loguids_state
       FROM (
           SELECT
               _adomoid,
               dvid,
               timescale,
               devlogtype,
               epid,
               euid,
               dstepid,
               dsteuid,
               dstip,
               srcip,
               app,
               f_user,
               keywords,
               category,
               host_name,
               maxMerge(avatar_state) AS avatar,
               groupUniqArrayMerge(10)(inspected_data_state) AS inspected_data,
               safeguardMatchMergeState(match_state) AS match,
               sumMerge(count_state) AS count,
               minMerge(min_itime_state) AS min_itime,
               maxMerge(max_itime_state) AS max_itime,
               groupArrayMerge(100)(loguids_state) AS loguids
          FROM siem.fv_fgt_u_safeguard_match_hour_sp$SPID
          GROUP BY _adomoid, dvid, timescale,
                   devlogtype, epid, euid, dstepid, dsteuid, dstip, srcip, app, f_user, keywords, category, host_name
)
GROUP BY _adomoid, dvid, timescale,
         devlogtype, epid, euid, dstepid, dsteuid, dstip, srcip, app, f_user, keywords, category, host_name;

ALTER TABLE siem.fv_fgt_u_safeguard_match_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
