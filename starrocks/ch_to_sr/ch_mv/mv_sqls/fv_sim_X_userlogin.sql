/*
 {
    "type": "norm_all_adom_mv",
    "version": "070602.6339",
    "name": "fv_sim_X_userlogin",
    "datasource_mv": "fv_sim_X_userlogin_day_mv_adom$ADOMOID"
 }
 */
DROP TABLE IF EXISTS siem.fv_sim_X_userlogin_day_mv_adom$ADOMOID;
DROP TABLE IF EXISTS siem.fv_sim_X_userlogin_day_adom$ADOMOID;

CREATE TABLE IF NOT EXISTS siem.fv_sim_X_userlogin_day_adom$ADOMOID (
    adom_oid UInt64,
    itime DateTime,
    loguid UInt64,
    user_id Nullable(String),
    euid UInt32,
    epid UInt32,
    src_ip Nullable(IPv6),
    src_geo LowCardinality(Nullable(String)),
    host_name LowCardinality(Nullable(String)),
    data_sourcetype LowCardinality(String),
    data_sourceid LowCardinality(String),
    d_source_vdom LowCardinality(Nullable(String))
) ENGINE = AggregatingMergeTree()
ORDER BY (adom_oid, itime, euid, src_ip)
PARTITION BY toYYYYMMDD(itime)
TTL itime + INTERVAL 2 DAY DELETE
SETTINGS index_granularity = 8192, allow_nullable_key = 1, ttl_only_drop_parts=1 $STORAGE;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_sim_X_userlogin_day_mv_adom$ADOMOID TO siem.fv_sim_X_userlogin_day_adom$ADOMOID AS
SELECT
    adom_oid,
    itime,
    loguid,
    user_id,
    euid,
    epid,
    src_ip,
    src_geo,
    host_name,
    data_sourcetype,
    data_sourceid,
    coalesce(
        splitByChar(' ', coalesce(data_sourcename, '')) [-1],
        'root'
    ) AS d_source_vdom
FROM
   $LOG
WHERE
    data_sourcetype = 'FortiAuthenticator'
    and euid > 1024
    and app_state = 'Success'
    and event_action = 'Authentication'
    and event_subtype != 'Web'
    and src_geo IS NOT NULL
    and (toInt32OrNull(src_geo) IS NOT NULL)
    and src_geo not in ('0', '');

ALTER TABLE siem.fv_sim_X_userlogin_day_mv_adom$ADOMOID MODIFY COMMENT '$VERSION';