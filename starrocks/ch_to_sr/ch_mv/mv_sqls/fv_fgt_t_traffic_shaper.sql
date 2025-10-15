/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fgt_t_traffic_shaper",
    "datasource_mv": "fv_fgt_t_traffic_shaper_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_t_traffic_shaper_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_traffic_shaper_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_traffic_shaper_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_traffic_shaper_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_traffic_shaper_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_t_traffic_shaper_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_traffic_shaper_5min_sp$SPID (
    dvid Int32, timescale DateTime, _adomoid UInt64,
    shapingpolicyname Nullable(String), 
    shapingpolicyid Nullable(UInt32),
    service LowCardinality(Nullable(String)),
    app_group Nullable(String),
    srcintf LowCardinality(Nullable(String)),
    dstintf LowCardinality(Nullable(String)),
    shapersentname Nullable(String),
    shaperrcvdname Nullable(String),
    shaperperipname Nullable(String),
    f_user Nullable(String),
    srcip Nullable(IPv6),
    drop_bandwidth_state AggregateFunction(sum, Int64),
    shaperdroprcvdbyte_state AggregateFunction(sum, Int64),
    shaperdropsentbyte_state AggregateFunction(sum, Int64),
    shaperperipdropbyte_state AggregateFunction(sum, Int64),
    bandwidth_state AggregateFunction(sum, Int64),
    traffic_in_state AggregateFunction(sum, Int64),
    traffic_out_state AggregateFunction(sum, Int64),
    sdwan_on_state AggregateFunction(max, UInt8),
    sessions_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, shapingpolicyname, shapingpolicyid)
ORDER BY (_adomoid, dvid, timescale, 
          shapingpolicyname, shapingpolicyid, service, app_group,
          srcintf, dstintf, shapersentname, shaperrcvdname, shaperperipname,
          f_user, srcip)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;


CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_traffic_shaper_hour_sp$SPID AS siem.fv_fgt_t_traffic_shaper_5min_sp$SPID;


CREATE TABLE IF NOT EXISTS siem.fv_fgt_t_traffic_shaper_day_sp$SPID AS siem.fv_fgt_t_traffic_shaper_5min_sp$SPID;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_traffic_shaper_5min_mv_sp$SPID
TO siem.fv_fgt_t_traffic_shaper_5min_sp$SPID
AS SELECT _adomoid, dvid, 
    fv_timescale_func(itime, 300, 0) AS timescale,
    shapingpolicyname,
    shapingpolicyid,
    service,
    app_group,
    srcintf,
    dstintf,
    shapersentname,
    shaperrcvdname,
    shaperperipname,
    f_user,
    srcip,
    sumState(drop_bandwidth) AS drop_bandwidth_state,
    sumState(shaperdroprcvdbyte) AS shaperdroprcvdbyte_state,
    sumState(shaperdropsentbyte) AS shaperdropsentbyte_state,
    sumState(shaperperipdropbyte) AS shaperperipdropbyte_state,
    sumState(toInt64(bandwidth)) AS bandwidth_state,
    sumState(toInt64(traffic_in)) AS traffic_in_state,
    sumState(toInt64(traffic_out)) AS traffic_out_state,
    maxState(sdwan_on) AS sdwan_on_state,
    sumState(sessions) AS sessions_state
    FROM (
       SELECT
           itime,
           dvid,
           _adomoid,
           $LOGFIELD-shapingpolicyname, 
           $LOGFIELD-shapingpolicyid,
           $LOGFIELD-service,
           $LOGFIELD-srcintf,
           $LOGFIELD-dstintf,
           $LOGFIELD-shapersentname,
           $LOGFIELD-shaperrcvdname,
           $LOGFIELD-shaperperipname,
           $LOGFIELD-unauthuser,
           $LOGFIELD-user,
           coalesce(nullifna(user), nullifna(unauthuser)) AS f_user,
           $LOGFIELD-srcip,
           cast(coalesce($LOGFIELD_NOALIAS-shaperdropsentbyte,0), 'Int64') AS shaperdropsentbyte,
           cast(coalesce($LOGFIELD_NOALIAS-shaperdroprcvdbyte,0), 'Int64') AS shaperdroprcvdbyte,
           cast(coalesce($LOGFIELD_NOALIAS-shaperperipdropbyte,0), 'Int64') AS shaperperipdropbyte,
           $LOGFIELD-sentbyte,
           $LOGFIELD-rcvdbyte,
           $LOGFIELD-sentdelta,
           $LOGFIELD-rcvddelta,
           $LOGFIELD-vwlid,
           $LOGFIELD-app,
           app_group_name(app) AS app_group,
           coalesce(shaperdroprcvdbyte, 0)+coalesce(shaperdropsentbyte, 0)+coalesce(shaperperipdropbyte, 0) as drop_bandwidth,
           coalesce(sentdelta, sentbyte,0) + coalesce(rcvddelta,rcvdbyte, 0) AS bandwidth,
           coalesce(rcvddelta, rcvdbyte, 0) AS traffic_in,
           coalesce(sentdelta, sentbyte, 0) AS traffic_out,
           (CASE WHEN vwlid IS NOT NULL THEN 1 ELSE 0 END) AS sdwan_on,
           CAST(( CASE WHEN(bitAnd(logflag, 1) > 0) THEN 1 ELSE 0 END), 'Int64') AS sessions
      FROM siem.tlog_sp$SPID
      WHERE bitAnd(logflag, bitOr(1, 32)) > 0 AND _devlogtype = 10 AND (shapingpolicyid is not null OR shapingpolicyname is not null)
)
GROUP BY _adomoid, dvid, timescale,
     shapingpolicyname, shapingpolicyid, service, app_group, srcintf,
     dstintf, shapersentname, shaperrcvdname, shaperperipname,
     f_user, srcip;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_traffic_shaper_hour_mv_sp$SPID
TO siem.fv_fgt_t_traffic_shaper_hour_sp$SPID
AS SELECT
     _adomoid, dvid, 
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    shapingpolicyname,
    shapingpolicyid,
    service,
    app_group,
    srcintf,
    dstintf,
    shapersentname,
    shaperrcvdname,
    shaperperipname,
    f_user,
    srcip,
    sumState(drop_bandwidth) AS drop_bandwidth_state,
    sumState(shaperdroprcvdbyte) AS shaperdroprcvdbyte_state,
    sumState(shaperdropsentbyte) AS shaperdropsentbyte_state,
    sumState(shaperperipdropbyte) AS shaperperipdropbyte_state,
    sumState(bandwidth) AS bandwidth_state,
    sumState(traffic_in) AS traffic_in_state,
    sumState(traffic_out) AS traffic_out_state,
    maxState(sdwan_on) AS sdwan_on_state,
    sumState(sessions) AS sessions_state
    FROM (
       SELECT
         _adomoid, dvid, 
        timescale, 
        shapingpolicyname,
        shapingpolicyid,
        service,
        app_group,
        srcintf,
        dstintf,
        shapersentname,
        shaperrcvdname,
        shaperperipname,
        f_user,
        srcip,
        sumMerge(drop_bandwidth_state) AS drop_bandwidth,
        sumMerge(shaperdroprcvdbyte_state) AS shaperdroprcvdbyte,
        sumMerge(shaperdropsentbyte_state) AS shaperdropsentbyte,
        sumMerge(shaperperipdropbyte_state) AS shaperperipdropbyte,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(traffic_out_state) AS traffic_out,
        maxMerge(sdwan_on_state) AS sdwan_on,
        sumMerge(sessions_state) AS sessions
    FROM siem.fv_fgt_t_traffic_shaper_5min_sp$SPID
    GROUP BY _adomoid, dvid, timescale,
             shapingpolicyname, shapingpolicyid, service, app_group, srcintf,
             dstintf, shapersentname, shaperrcvdname, shaperperipname,
             f_user, srcip
)
GROUP BY _adomoid, dvid, timescale,
         shapingpolicyname, shapingpolicyid, service, app_group, srcintf,
         dstintf, shapersentname, shaperrcvdname, shaperperipname,
         f_user, srcip;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_t_traffic_shaper_day_mv_sp$SPID
TO siem.fv_fgt_t_traffic_shaper_day_sp$SPID
AS SELECT
     _adomoid, dvid, 
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    shapingpolicyname,
    shapingpolicyid,
    service,
    app_group,
    srcintf,
    dstintf,
    shapersentname,
    shaperrcvdname,
    shaperperipname,
    f_user,
    srcip,
    sumState(drop_bandwidth) AS drop_bandwidth_state,
    sumState(shaperdroprcvdbyte) AS shaperdroprcvdbyte_state,
    sumState(shaperdropsentbyte) AS shaperdropsentbyte_state,
    sumState(shaperperipdropbyte) AS shaperperipdropbyte_state,
    sumState(bandwidth) AS bandwidth_state,
    sumState(traffic_in) AS traffic_in_state,
    sumState(traffic_out) AS traffic_out_state,
    maxState(sdwan_on) AS sdwan_on_state,
    sumState(sessions) AS sessions_state
    FROM (
       SELECT
        _adomoid, dvid, 
        timescale, 
        shapingpolicyname,
        shapingpolicyid,
        service,
        app_group,
        srcintf,
        dstintf,
        shapersentname,
        shaperrcvdname,
        shaperperipname,
        f_user,
        srcip,
        sumMerge(drop_bandwidth_state) AS drop_bandwidth,
        sumMerge(shaperdroprcvdbyte_state) AS shaperdroprcvdbyte,
        sumMerge(shaperdropsentbyte_state) AS shaperdropsentbyte,
        sumMerge(shaperperipdropbyte_state) AS shaperperipdropbyte,
        sumMerge(bandwidth_state) AS bandwidth,
        sumMerge(traffic_in_state) AS traffic_in,
        sumMerge(traffic_out_state) AS traffic_out,
        maxMerge(sdwan_on_state) AS sdwan_on,
        sumMerge(sessions_state) AS sessions
    FROM siem.fv_fgt_t_traffic_shaper_hour_sp$SPID
    GROUP BY _adomoid, dvid, timescale,
             shapingpolicyname, shapingpolicyid, service, app_group, srcintf,
             dstintf, shapersentname, shaperrcvdname, shaperperipname,
             f_user, srcip
)
GROUP BY _adomoid, dvid, timescale,
         shapingpolicyname, shapingpolicyid, service, app_group, srcintf,
         dstintf, shapersentname, shaperrcvdname, shaperperipname,
         f_user, srcip;

ALTER TABLE siem.fv_fgt_t_traffic_shaper_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
