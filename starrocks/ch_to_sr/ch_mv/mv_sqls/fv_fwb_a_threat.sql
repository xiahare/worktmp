/*
{
    "type": "sp_mv",
    "version": "070600.3447",
    "name": "fv_fwb_a_threat",
    "datasource_mv": "fv_fwb_a_threat_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fwb_a_threat_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fwb_a_threat_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fwb_a_threat_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fwb_a_threat_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fwb_a_threat_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fwb_a_threat_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fwb_a_threat_5min_sp$SPID (
    timescale DateTime, dvid Int32,
    _adomoid UInt64,
    threat_level LowCardinality(Nullable(String)),
    num_block_state AggregateFunction(sum,Int64),
    num_alert_state AggregateFunction(sum,Int64),
    num_http_state AggregateFunction(sum,Int64),
    num_https_state AggregateFunction(sum,Int64),
    src Nullable(IPv6),
    dst Nullable(IPv6),
    srccountry Nullable(String),
    main_type Nullable(String),
    policy Nullable(String),
    dev_id Nullable(String),
    http_method Nullable(String),
    http_url Nullable(String),
    signature_cve_id Nullable(String),
    owasp_top10 Nullable(String),
    total_score_state AggregateFunction(sum,Int64),
    total_num_state AggregateFunction(sum,Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, threat_level, src, dst)
ORDER BY (_adomoid, dvid, timescale, threat_level,
         src, dst, srccountry, main_type, policy)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;

CREATE TABLE IF NOT EXISTS siem.fv_fwb_a_threat_hour_sp$SPID AS siem.fv_fwb_a_threat_5min_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fwb_a_threat_day_sp$SPID AS siem.fv_fwb_a_threat_5min_sp$SPID;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fwb_a_threat_5min_mv_sp$SPID
TO siem.fv_fwb_a_threat_5min_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(itime, 300, 0) AS timescale,
       threat_level,
       sumState(toInt64(num_block)) AS num_block_state,
       sumState(toInt64(num_alert)) AS num_alert_state,
       sumState(toInt64(num_http)) AS num_http_state,
       sumState(toInt64(num_https)) AS num_https_state,
       src,
       dst,
       srccountry,
       main_type,
       policy,
       dev_id,
       http_method,
       http_url,
       signature_cve_id,
       owasp_top10,
       sumState(toInt64(total_score)) AS total_score_state,
       sumState(toInt64(total_num)) AS total_num_state
       FROM (
           SELECT
               itime,
               dvid,
               _adomoid,
               _devlogtype,
               $LOGFIELD-action,
               $LOGFIELD-service,
               $LOGFIELD-threat_level,
               (CASE WHEN action IN ('Alert_Deny', 'Return_4xx', 'Return_5xx', 'Redirect', 'Period_Block', 'Send_HTTP_Response', 'Return_403_error') THEN 1 ELSE 0 END) AS num_block,
               (CASE WHEN action IN ('Alert', 'Erase', 'Erase_Only', 'Remove_cookie') THEN 1 ELSE 0 END) AS num_alert,
               (CASE WHEN service IN ('http') THEN 1 ELSE 0 END) AS num_http,
               (CASE WHEN service IN ('https', 'https/tls1.0', 'https/tls1.1', 'https/tls1.2', 'https/tls1.3') THEN 1 ELSE 0 END) AS num_https,
               $LOGFIELD-src,
               $LOGFIELD-dst,
               $LOGFIELD-srccountry,
               $LOGFIELD-main_type,
               $LOGFIELD-policy,
               $LOGFIELD-dev_id,
               $LOGFIELD-http_method,
               $LOGFIELD-http_url,
               $LOGFIELD-signature_cve_id,
               $LOGFIELD-owasp_top10,
               $LOGFIELD-threat_weight,
               coalesce(threat_weight,0) AS total_score,
               1 AS total_num
          FROM siem.ulog_sp$SPID
          WHERE  _devlogtype = 5001 AND service NOT IN ('ftp', 'ftps')
)
GROUP BY _adomoid, dvid, timescale, threat_level,
         src, dst, srccountry, main_type, policy, dev_id,
         http_method, http_url, signature_cve_id, owasp_top10;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fwb_a_threat_hour_mv_sp$SPID
TO siem.fv_fwb_a_threat_hour_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 3600, 0) AS timescale,
       threat_level,
       sumState(toInt64(num_block)) AS num_block_state,
       sumState(toInt64(num_alert)) AS num_alert_state,
       sumState(toInt64(num_http)) AS num_http_state,
       sumState(toInt64(num_https)) AS num_https_state,
       src,
       dst,
       srccountry,
       main_type,
       policy, 
       dev_id,
       http_method,
       http_url,
       signature_cve_id,
       owasp_top10,
       sumState(toInt64(total_score)) AS total_score_state,
       sumState(toInt64(total_num)) AS total_num_state
FROM (
   SELECT _adomoid, dvid,
       timescale,

       threat_level,
       sumMerge(num_block_state) AS num_block,
       sumMerge(num_alert_state) AS num_alert,
       sumMerge(num_http_state) AS num_http,
       sumMerge(num_https_state) AS num_https,
       src,
       dst,
       srccountry,
       main_type,
       policy, 
       dev_id,
       http_method,
       http_url,
       signature_cve_id,
       owasp_top10,
       sumMerge(total_score_state) AS total_score,
       sumMerge(total_num_state) AS total_num
    FROM siem.fv_fwb_a_threat_5min_sp$SPID
    GROUP BY _adomoid, dvid, timescale, threat_level,
         src, dst, srccountry, main_type, policy, dev_id,
         http_method, http_url, signature_cve_id, owasp_top10
)
GROUP BY _adomoid, dvid, timescale, threat_level,
         src, dst, srccountry, main_type, policy, dev_id,
         http_method, http_url, signature_cve_id, owasp_top10;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fwb_a_threat_day_mv_sp$SPID
TO siem.fv_fwb_a_threat_day_sp$SPID
AS SELECT _adomoid, dvid,
       fv_timescale_func(timescale, 28800, 0) AS timescale,
       threat_level,
       sumState(toInt64(num_block)) AS num_block_state,
       sumState(toInt64(num_alert)) AS num_alert_state,
       sumState(toInt64(num_http)) AS num_http_state,
       sumState(toInt64(num_https)) AS num_https_state,
       src,
       dst,
       srccountry,
       main_type,
       policy, 
       dev_id,
       http_method,
       http_url,
       signature_cve_id,
       owasp_top10,
       sumState(toInt64(total_score)) AS total_score_state,
       sumState(toInt64(total_num)) AS total_num_state
FROM (
   SELECT _adomoid, dvid,
       timescale,
       threat_level,
       sumMerge(num_block_state) AS num_block,
       sumMerge(num_alert_state) AS num_alert,
       sumMerge(num_http_state) AS num_http,
       sumMerge(num_https_state) AS num_https,
       src,
       dst,
       srccountry,
       main_type,
       policy, 
       dev_id,
       http_method,
       http_url,
       signature_cve_id,
       owasp_top10,
       sumMerge(total_score_state) AS total_score,
       sumMerge(total_num_state) AS total_num
    FROM siem.fv_fwb_a_threat_hour_sp$SPID
    GROUP BY _adomoid, dvid, timescale, threat_level,
         src, dst, srccountry, main_type, policy, dev_id,
         http_method, http_url, signature_cve_id, owasp_top10
)
GROUP BY _adomoid, dvid, timescale, threat_level,
         src, dst, srccountry, main_type, policy, dev_id,
         http_method, http_url, signature_cve_id, owasp_top10;

ALTER TABLE siem.fv_fwb_a_threat_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
