/*
{
    "datasource_mv": "fv_sim_X_ztna_dev_tags_5min_mv_adom$ADOMOID",
    "version": "070601.3382",
    "type": "norm_all_adom_mv",
    "name": "fv_sim_X_ztna_dev_tags"
}
*/
DROP TABLE IF EXISTS siem.fv_sim_X_ztna_dev_tags_5min_mv_adom$ADOMOID;
DROP TABLE IF EXISTS siem.fv_sim_X_ztna_dev_tags_hour_mv_adom$ADOMOID;
DROP TABLE IF EXISTS siem.fv_sim_X_ztna_dev_tags_day_mv_adom$ADOMOID;
DROP TABLE IF EXISTS siem.fv_sim_X_ztna_dev_tags_5min_adom$ADOMOID;
DROP TABLE IF EXISTS siem.fv_sim_X_ztna_dev_tags_hour_adom$ADOMOID;
DROP TABLE IF EXISTS siem.fv_sim_X_ztna_dev_tags_day_adom$ADOMOID;

CREATE TABLE IF NOT EXISTS siem.fv_sim_X_ztna_dev_tags_5min_adom$ADOMOID (
    timescale DateTime, data_sourceid String,
    data_sourcevdom String,
    f_user Nullable(String),
    adom_oid UInt64,
    dev_tag Nullable(String),
    dstintf LowCardinality(Nullable(String)),
    dstip Nullable(IPv6),
    srcip Nullable(IPv6),
    srcintf LowCardinality(Nullable(String)),
    srcmac Nullable(String),
    policyid Nullable(UInt32),
    policytype LowCardinality(Nullable(String)),
    policyname Nullable(String),
    accessproxy Nullable(String),
    dev_src  Nullable(String),
    devtype Nullable(String),
    count_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (adom_oid, timescale, data_sourceid, data_sourcevdom, accessproxy, dev_tag, dev_src, devtype, f_user)
ORDER BY (adom_oid, timescale,  data_sourceid, data_sourcevdom,
          accessproxy, dev_tag, dev_src, devtype, f_user,
          srcip, srcintf, srcmac, dstip, dstintf,
          policyname, policyid, policytype)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;
CREATE TABLE IF NOT EXISTS siem.fv_sim_X_ztna_dev_tags_hour_adom$ADOMOID AS siem.fv_sim_X_ztna_dev_tags_5min_adom$ADOMOID;
CREATE TABLE IF NOT EXISTS siem.fv_sim_X_ztna_dev_tags_day_adom$ADOMOID AS siem.fv_sim_X_ztna_dev_tags_5min_adom$ADOMOID;
CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_sim_X_ztna_dev_tags_5min_mv_adom$ADOMOID
TO siem.fv_sim_X_ztna_dev_tags_5min_adom$ADOMOID
AS SELECT
    adom_oid, data_sourceid,
    data_sourcevdom,
    dev_tag,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    f_user,
    srcip, 
    srcintf, 
    srcmac,
    dev_src,
    dstip,
    dstintf,
    devtype,
    policyid,
    policytype,
    policyname,
    accessproxy,
    sumState(toInt64(count)) AS count_state
    FROM (
       SELECT
        adom_oid, data_sourceid,
        data_sourcevdom,
        itime AS timescale,
        coalesce(nullifna(user_name), nullifna(user_unauthuser)) AS f_user,
        src_ip AS srcip, 
        src_intf as srcintf,
        src_mac AS srcmac,
        coalesce(src_domain, src_mac) AS dev_src,
        dst_ip AS dstip,
        dst_intf AS dstintf,
        get_devtype(host_osver, host_osname, data_sourcetype) AS devtype,
        event_policyid AS policyid,
        event_policytype AS policytype,
        event_policy AS policyname,
        json_extract(app_access, 'accessproxy') AS accessproxy,
        arrayJoin(splitByChar('/', coalesce(json_extract(host_data, 'tags'),''))) AS dev_tag,
        count(*) AS count
      FROM $LOG
      WHERE event_type = 'traffic' AND accessproxy IS NOT NULL AND
            json_extract(host_data, 'tags') IS NOT NULL
      GROUP BY adom_oid, data_sourceid, data_sourcevdom, timescale,
               accessproxy, dev_tag, dev_src, devtype, f_user,
               srcip, srcintf, srcmac, dstip, dstintf,
               policyname, policyid, policytype
)
GROUP BY adom_oid, data_sourceid, data_sourcevdom, timescale,
         accessproxy, dev_tag, dev_src, devtype, f_user,
         srcip, srcintf, srcmac, dstip, dstintf,
         policyname, policyid, policytype;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_sim_X_ztna_dev_tags_hour_mv_adom$ADOMOID
TO siem.fv_sim_X_ztna_dev_tags_hour_adom$ADOMOID
AS SELECT
    adom_oid, data_sourceid,
    data_sourcevdom,
    dev_tag,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    f_user,
    srcip, 
    srcintf,
    srcmac,
    dev_src,
    dstip,
    dstintf,
    devtype,
    policyid,
    policytype,
    policyname,
    accessproxy,
    sumState(count) AS count_state
    FROM (
       SELECT
        adom_oid, data_sourceid,
        data_sourcevdom,
        dev_tag,
        timescale,
        f_user,
        srcip, 
        srcintf,
        srcmac,
        dev_src,
        dstip,
        dstintf,
        devtype,
        policyid,
        policytype,
        policyname,
        accessproxy,
        sumMerge(count_state) AS count
      FROM siem.fv_sim_X_ztna_dev_tags_5min_adom$ADOMOID
      GROUP BY adom_oid, data_sourceid, data_sourcevdom, timescale,
               accessproxy, dev_tag, dev_src, devtype, f_user,
               srcip, srcintf, srcmac, dstip, dstintf,
               policyname, policyid, policytype
)
GROUP BY adom_oid, data_sourceid, data_sourcevdom, timescale,
         accessproxy, dev_tag, dev_src, devtype, f_user,
         srcip, srcintf, srcmac, dstip, dstintf,
         policyname, policyid, policytype;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_sim_X_ztna_dev_tags_day_mv_adom$ADOMOID
TO siem.fv_sim_X_ztna_dev_tags_day_adom$ADOMOID
AS SELECT
    adom_oid, data_sourceid,
    data_sourcevdom,
    dev_tag,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    f_user,
    srcip, 
    srcintf,
    srcmac,
    dev_src,
    dstip,
    dstintf,
    devtype,
    policyid,
    policytype,
    policyname,
    accessproxy,
    sumState(count) AS count_state
    FROM (
       SELECT
        adom_oid, data_sourceid,
        data_sourcevdom,
        dev_tag,
        timescale,
        f_user,
        srcip, 
        srcintf, 
        srcmac,
        dev_src,
        dstip,
        dstintf,
        devtype,
        policyid,
        policytype,
        policyname,
        accessproxy,
        sumMerge(count_state) AS count
      FROM siem.fv_sim_X_ztna_dev_tags_hour_adom$ADOMOID
      GROUP BY adom_oid, data_sourceid, data_sourcevdom, timescale,
               accessproxy, dev_tag, dev_src, devtype, f_user,
               srcip, srcintf, srcmac, dstip, dstintf,
               policyname, policyid, policytype
)
GROUP BY adom_oid, data_sourceid, data_sourcevdom, timescale,
         accessproxy, dev_tag, dev_src, devtype, f_user,
         srcip, srcintf, srcmac, srcmac, dstip, dstintf,
         policyname, policyid, policytype;

ALTER TABLE siem.fv_sim_X_ztna_dev_tags_day_mv_adom$ADOMOID MODIFY COMMENT '$VERSION';
