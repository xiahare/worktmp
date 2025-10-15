/*
 {
    "type": "norm_all_adom_mv",
    "version": "070602.6338",
    "name": "fv_sim_X_userlogin_src_geo",
    "datasource_mv": "fv_sim_X_userlogin_src_geo_day_mv_adom$ADOMOID"
 }
 */
DROP TABLE IF EXISTS siem.fv_sim_X_userlogin_src_geo_day_mv_adom$ADOMOID;
DROP TABLE IF EXISTS siem.fv_sim_X_userlogin_src_geo_day_adom$ADOMOID;

CREATE TABLE IF NOT EXISTS siem.fv_sim_X_userlogin_src_geo_day_adom$ADOMOID (
    adom_oid UInt64,
    timescale DateTime,
    euid UInt32,
    src_geo LowCardinality(Nullable(String)),
    geo_cnt AggregateFunction(count)
) ENGINE = AggregatingMergeTree()
ORDER BY (adom_oid, timescale, euid, src_geo)
PARTITION BY toYYYYMMDD(timescale)
TTL timescale + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192, allow_nullable_key = 1, ttl_only_drop_parts=1 $STORAGE;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_sim_X_userlogin_src_geo_day_mv_adom$ADOMOID TO siem.fv_sim_X_userlogin_src_geo_day_adom$ADOMOID AS
SELECT
    adom_oid,
    fv_timescale_func(itime, 86400, 0) AS timescale,
    euid,
    src_geo,
    countState() AS geo_cnt
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
    and src_geo not in ('0', '1000000000', '')
GROUP BY adom_oid, timescale, euid, src_geo;

ALTER TABLE siem.fv_sim_X_userlogin_src_geo_day_mv_adom$ADOMOID MODIFY COMMENT '$VERSION';