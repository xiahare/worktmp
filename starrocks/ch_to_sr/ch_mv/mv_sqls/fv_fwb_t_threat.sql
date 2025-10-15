/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fwb_t_threat",
    "datasource_mv": "fv_fwb_t_threat_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fwb_t_threat_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fwb_t_threat_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fwb_t_threat_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fwb_t_threat_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fwb_t_threat_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fwb_t_threat_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fwb_t_threat_5min_sp$SPID (
    timescale DateTime, dvid Int32,
    _adomoid UInt64,
    total_v1_state AggregateFunction(sum,Int64),
    total_v2_state AggregateFunction(sum,Int64),
    num_http_state AggregateFunction(sum,Int64),
    num_https_state AggregateFunction(sum,Int64),
    req_bytes_state AggregateFunction(sum,Int64),
    resp_bytes_state AggregateFunction(sum,Int64),
    total_bytes_state AggregateFunction(sum,Int64),
    src Nullable(IPv6),
    dst Nullable(IPv6),
    srccountry Nullable(String),
    original_src Nullable(IPv6), 
    original_srccountry Nullable(String),
    policy Nullable(String),
    http_host Nullable(String),
    http_method Nullable(String),
    http_url Nullable(String),
    http_retcode Nullable(UInt16),
    total_num_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, src, dst, srccountry, original_src)
ORDER BY (_adomoid, dvid, timescale,
          src, dst, srccountry, original_src, original_srccountry, policy,
          http_host, http_method, http_url, http_retcode)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fwb_t_threat_hour_sp$SPID AS siem.fv_fwb_t_threat_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fwb_t_threat_day_sp$SPID AS siem.fv_fwb_t_threat_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fwb_t_threat_5min_mv_sp$SPID
TO siem.fv_fwb_t_threat_5min_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(itime, 300, 0) AS timescale,
       src, dst, srccountry, original_src, original_srccountry, policy, 
       http_host, http_method, http_url, http_retcode,
       sumState(toInt64(total_v1)) AS total_v1_state,
       sumState(toInt64(total_v2)) AS total_v2_state,
       sumState(toInt64(num_http)) AS num_http_state,
       sumState(toInt64(num_https)) AS num_https_state,
       sumState(toInt64(req_bytes)) AS req_bytes_state,
       sumState(toInt64(resp_bytes)) AS resp_bytes_state,
       sumState(toInt64(total_bytes)) AS total_bytes_state,
       sumState(toInt64(total_num)) AS total_num_state
       FROM (
           SELECT
               itime,
               dvid,
               _adomoid,
               _devlogtype,
               $LOGFIELD-http_version,
               $LOGFIELD-service,
               $LOGFIELD-http_request_bytes,
               $LOGFIELD-http_response_bytes,
               $LOGFIELD-src,
               $LOGFIELD-dst,
               $LOGFIELD-srccountry,
               $LOGFIELD-policy,
               $LOGFIELD-http_host,
               $LOGFIELD-http_method,
               $LOGFIELD-http_url,
               $LOGFIELD-http_retcode,
               $LOGFIELD-original_src,
               $LOGFIELD-original_srccountry,
               (CASE WHEN http_version = '1.x' THEN 1 ELSE 0 END) AS total_v1,
               (CASE WHEN http_version = '2.0' THEN 1 ELSE 0 END) AS total_v2,
               (CASE WHEN service IN ('http') THEN 1 ELSE 0 END) AS num_http,
               (CASE WHEN service IN ('https', 'https/tls1.0', 'https/tls1.1', 'https/tls1.2', 'https/tls1.3') THEN 1 ELSE 0 END) AS num_https,
               (coalesce(http_request_bytes, 0)) as req_bytes,
               (coalesce(http_response_bytes, 0)) as resp_bytes,
               (coalesce(http_request_bytes, 0)+coalesce(http_response_bytes, 0)) as total_bytes,
               src, dst, srccountry, policy,
               http_host, http_method, http_url, http_retcode,
               1 AS total_num
          FROM siem.ulog_sp$SPID
          WHERE  _devlogtype = 5010 AND service NOT IN ('ftp', 'ftps')
)
GROUP BY _adomoid, dvid, timescale,
     src, dst, srccountry, original_src, original_srccountry, policy,
     http_host, http_method, http_url, http_retcode;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fwb_t_threat_hour_mv_sp$SPID
TO siem.fv_fwb_t_threat_hour_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 3600, 0) AS timescale,
       src, dst, srccountry, original_src, original_srccountry, policy,
       http_host, http_method, http_url, http_retcode,
       sumState(total_v1) AS total_v1_state,
       sumState(total_v2) AS total_v2_state,
       sumState(num_http) AS num_http_state,
       sumState(num_https) AS num_https_state,
       sumState(req_bytes) AS req_bytes_state,
       sumState(resp_bytes) AS resp_bytes_state,
       sumState(total_bytes) AS total_bytes_state,
       sumState(total_num) AS total_num_state
FROM (
   SELECT _adomoid, dvid,
       timescale,
       src, dst, srccountry, original_src, original_srccountry, policy,
       http_host, http_method, http_url, http_retcode,
       sumMerge(total_v1_state) AS total_v1,
       sumMerge(total_v2_state) AS total_v2,
       sumMerge(num_http_state) AS num_http,
       sumMerge(num_https_state) AS num_https,
       sumMerge(req_bytes_state) AS req_bytes,
       sumMerge(resp_bytes_state) AS resp_bytes,
       sumMerge(total_bytes_state) AS total_bytes,
       sumMerge(total_num_state) AS total_num
    FROM siem.fv_fwb_t_threat_5min_sp$SPID
    GROUP BY _adomoid, dvid, timescale,
             src, dst, srccountry, original_src, original_srccountry, policy,
             http_host, http_method, http_url, http_retcode
)
GROUP BY _adomoid, dvid, timescale,
         src, dst, srccountry, original_src, original_srccountry, policy,
         http_host, http_method, http_url, http_retcode;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fwb_t_threat_day_mv_sp$SPID
TO siem.fv_fwb_t_threat_day_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 28800, 0) AS timescale,
       src, dst, srccountry, original_src, original_srccountry, policy,
       http_host, http_method, http_url, http_retcode,
       sumState(total_v1) AS total_v1_state,
       sumState(total_v2) AS total_v2_state,
       sumState(num_http) AS num_http_state,
       sumState(num_https) AS num_https_state,
       sumState(req_bytes) AS req_bytes_state,
       sumState(resp_bytes) AS resp_bytes_state,
       sumState(total_bytes) AS total_bytes_state,
       sumState(total_num) AS total_num_state
FROM (
   SELECT _adomoid, dvid,
       timescale,
       src, dst, srccountry, original_src, original_srccountry, policy,
       http_host, http_method, http_url, http_retcode,
       sumMerge(total_v1_state) AS total_v1,
       sumMerge(total_v2_state) AS total_v2,
       sumMerge(num_http_state) AS num_http,
       sumMerge(num_https_state) AS num_https,
       sumMerge(req_bytes_state) AS req_bytes,
       sumMerge(resp_bytes_state) AS resp_bytes,
       sumMerge(total_bytes_state) AS total_bytes,
       sumMerge(total_num_state) AS total_num
    FROM siem.fv_fwb_t_threat_hour_sp$SPID
    GROUP BY _adomoid, dvid, timescale,
             src, dst, srccountry, original_src, original_srccountry, policy,
             http_host, http_method, http_url, http_retcode
)
GROUP BY _adomoid, dvid, timescale,
         src, dst, srccountry, original_src, original_srccountry, policy,
         http_host, http_method, http_url, http_retcode;

ALTER TABLE siem.fv_fwb_t_threat_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
