/*
{
    "type": "sp_mv",
    "version": "070600.3329",
    "name": "fv_fpx_e_unauthorized",
    "datasource_mv": "fv_fpx_e_unauthorized_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fpx_e_unauthorized_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fpx_e_unauthorized_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fpx_e_unauthorized_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fpx_e_unauthorized_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fpx_e_unauthorized_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fpx_e_unauthorized_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fpx_e_unauthorized_5min_sp$SPID (
    _adomoid UInt64,
    dvid Int32,
    timescale DateTime,
    user LowCardinality(Nullable(String)),
    subtype LowCardinality(String),
    logintype Int8,
    ui Nullable(String),
    vpntunnel LowCardinality(Nullable(String)),
    policyid Nullable(UInt32),
    ssid Nullable(String),
    srcip Nullable(IPv6),
    method LowCardinality(Nullable(String)),
    dstip Nullable(IPv6),
    remip Nullable(IPv6),
    xauthuser Nullable(String),
    initiator Nullable(String),
    stamac  Nullable(String),
    interface Nullable(String),
    community Nullable(String),
    logid UInt64,
    total_num_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, dvid, timescale, user)
ORDER BY (_adomoid, dvid, timescale, user, subtype, logintype,
          ui, vpntunnel, policyid, ssid, srcip, method,
          dstip, remip, xauthuser, initiator, stamac, interface,
          community, logid)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;


CREATE TABLE IF NOT EXISTS siem.fv_fpx_e_unauthorized_hour_sp$SPID AS siem.fv_fpx_e_unauthorized_5min_sp$SPID;


CREATE TABLE IF NOT EXISTS siem.fv_fpx_e_unauthorized_day_sp$SPID AS siem.fv_fpx_e_unauthorized_5min_sp$SPID;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fpx_e_unauthorized_5min_mv_sp$SPID
TO siem.fv_fpx_e_unauthorized_5min_sp$SPID
AS SELECT 
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    user, subtype, logintype, ui, vpntunnel, policyid,
    ssid, srcip, method, dstip, remip, xauthuser, initiator,
    stamac, interface, community, logid,
    sumState(toInt64(total_num)) AS total_num_state
FROM (
      SELECT
        _adomoid,
        dvid,
        itime AS timescale,
        $LOGFIELD-user,
        subtype,
        $LOGFIELD-ui,
        $LOGFIELD-vpntunnel,
        $LOGFIELD-policyid,
        $LOGFIELD-ssid,
        $LOGFIELD-srcip,
        $LOGFIELD-method,
        $LOGFIELD-dstip,
        $LOGFIELD-remip,
        $LOGFIELD-xauthuser,
        $LOGFIELD-initiator,
        $LOGFIELD-stamac, 
        $LOGFIELD-interface,
        $LOGFIELD-community,
        $LOGFIELD-action,
        logid,
        logid_to_int(logid) AS logid_as_uint64,
        (CASE
             WHEN logid_as_uint64 IN (32002,
                                   32024) THEN 1
             WHEN logid_as_uint64 = 39426 THEN 2
             WHEN logid_as_uint64 IN (37121,
                                   37124,
                                   37185,
                                   37188) THEN 3
             WHEN logid_as_uint64 IN (43009,
                                   43010) THEN 4
             WHEN logid_as_uint64 IN (43018,
                                   43030) THEN 5
             WHEN (subtype='wireless'
                   AND action='user-sign-on-failure') THEN 6
             WHEN logid_as_uint64 = 29021 THEN 7
             ELSE 0
         END) AS logintype,
         1 AS total_num
      FROM siem.elog_sp$SPID
      WHERE _devlogtype= 15005
            AND (logid_as_uint64 IN (32002, 32024, 39426, 37121, 37124, 37185, 37188, 43009, 43010, 43018, 43030, 29021)
              OR (subtype='wireless' AND action='user-sign-on-failure'))
)
GROUP BY _adomoid, dvid, timescale,
     `user`, subtype, logintype, ui, vpntunnel,
     policyid, ssid, srcip, method, dstip, remip,
     xauthuser, initiator, stamac, interface, community, logid;



CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fpx_e_unauthorized_hour_mv_sp$SPID
TO siem.fv_fpx_e_unauthorized_hour_sp$SPID
AS SELECT 
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    user,
    subtype,
    logintype,
    ui,
    vpntunnel,
    policyid,
    ssid,
    srcip,
    method,
    dstip,
    remip,
    xauthuser,
    initiator,
    stamac,
    interface,
    community,
    logid,
    sumState(total_num) AS total_num_state
FROM (
      SELECT
        _adomoid,
        dvid,
        fv_timescale_func(timescale, 3600, 0) AS timescale,
        user,
        subtype,
        logintype,
        ui,
        vpntunnel,
        policyid,
        ssid,
        srcip,
        method,
        dstip,
        remip,
        xauthuser,
        initiator,
        stamac,
        interface,
        community,
        logid,
        sumMerge(total_num_state) AS total_num
      FROM siem.fv_fpx_e_unauthorized_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale,
         `user`, subtype, logintype, ui, vpntunnel,
         policyid, ssid, srcip, method, dstip, remip,
         xauthuser, initiator, stamac, interface, community, logid
)
GROUP BY _adomoid, dvid, timescale,
     `user`, subtype, logintype, ui, vpntunnel,
     policyid, ssid, srcip, method, dstip, remip,
     xauthuser, initiator, stamac, interface, community, logid;


CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fpx_e_unauthorized_day_mv_sp$SPID
TO siem.fv_fpx_e_unauthorized_day_sp$SPID
AS SELECT 
    _adomoid,
    dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    user,
    subtype,
    logintype,
    ui,
    vpntunnel,
    policyid,
    ssid,
    srcip,
    method,
    dstip,
    remip,
    xauthuser,
    initiator,
    stamac,
    interface,
    community,
    logid,
    sumState(total_num) AS total_num_state
FROM (
      SELECT
        _adomoid,
        dvid,
        timescale,
        user,
        subtype,
        logintype,
        ui,
        vpntunnel,
        policyid,
        ssid,
        srcip,
        method,
        dstip,
        remip,
        xauthuser,
        initiator,
        stamac,
        interface,
        community,
        logid,
        sumMerge(total_num_state) AS total_num
      FROM siem.fv_fpx_e_unauthorized_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale,
         `user`, subtype, logintype, ui, vpntunnel,
         policyid, ssid, srcip, method, dstip, remip,
         xauthuser, initiator, stamac, interface, community, logid

)
GROUP BY _adomoid, dvid, timescale,
     `user`, subtype, logintype, ui, vpntunnel,
     policyid, ssid, srcip, method, dstip, remip,
     xauthuser, initiator, stamac, interface, community, logid;

ALTER TABLE siem.fv_fpx_e_unauthorized_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
