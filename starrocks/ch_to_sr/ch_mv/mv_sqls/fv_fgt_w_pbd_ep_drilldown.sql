/*
{
    "type": "sp_mv",
    "version": "070600.3459",
    "name": "fv_fgt_w_pbd_ep_drilldown",
    "datasource_mv": "fv_fgt_w_pbd_ep_drilldown_5min_mv_sp$SPID"
}
*/
DROP TABLE IF EXISTS siem.fv_fgt_w_pbd_ep_drilldown_5min_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_w_pbd_ep_drilldown_hour_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_w_pbd_ep_drilldown_day_mv_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_w_pbd_ep_drilldown_5min_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_w_pbd_ep_drilldown_hour_sp$SPID;
DROP TABLE IF EXISTS siem.fv_fgt_w_pbd_ep_drilldown_day_sp$SPID;

CREATE TABLE IF NOT EXISTS siem.fv_fgt_w_pbd_ep_drilldown_5min_sp$SPID (
    dvid Int32,
    timescale DateTime, _adomoid UInt64,
    epid Nullable(Int32),
    srcip Nullable(IPv6),
    dstip Nullable(IPv6),
    f_user Nullable(String),
    action LowCardinality(Nullable(String)),
    tdtype LowCardinality(Nullable(String)),
    tdpattern Nullable(String),
    tdinfoid Nullable(Int64),
    tdthreattype Nullable(Int32),
    threattype LowCardinality(Nullable(String)),
    tdthreatname Nullable(UInt16),
    threatname Nullable(String),
    tdscantime Nullable(DateTime),
    tdwfcate Nullable(UInt16),
    webcat Nullable(String),
    tdscore_state AggregateFunction(sum, Nullable(Int64)),
    event_num_state AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PRIMARY KEY (_adomoid, timescale, dvid, epid, srcip, dstip)
ORDER BY (_adomoid, timescale, dvid, epid, srcip, dstip, f_user, action, tdtype,
          tdthreattype, tdthreatname, tdwfcate, tdscantime,
          tdpattern, tdinfoid, threattype, threatname, webcat)
PARTITION BY toYYYYMMDD(timescale)
SETTINGS index_granularity = 8192, allow_nullable_key = 1 $STORAGE;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_w_pbd_ep_drilldown_hour_sp$SPID AS siem.fv_fgt_w_pbd_ep_drilldown_5min_sp$SPID;
CREATE TABLE IF NOT EXISTS siem.fv_fgt_w_pbd_ep_drilldown_day_sp$SPID AS siem.fv_fgt_w_pbd_ep_drilldown_5min_sp$SPID;
CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_w_pbd_ep_drilldown_5min_mv_sp$SPID
TO siem.fv_fgt_w_pbd_ep_drilldown_5min_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 300, 0) AS timescale,
    epid, srcip, dstip, f_user, action, tdtype, tdpattern, tdinfoid,
    tdthreattype, threattype, tdthreatname, threatname, tdscantime,
    tdwfcate, webcat,
    sumState(toInt64(tdscore)) AS tdscore_state,
    sumState(toInt64(event_num)) AS event_num_state
    FROM (
       SELECT
        _adomoid, dvid,
        itime AS timescale,
        epid,
        $LOGFIELD-srcip, 
        $LOGFIELD-dstip,
        coalesce(nullifna($LOGFIELD_NOALIAS-user), nullifna($LOGFIELD_NOALIAS-unauthuser)) AS f_user,
        $LOGFIELD-action,
        $LOGFIELD-tdtype,
        $LOGFIELD-tdscantime,
        $LOGFIELD-tdthreattype-_tdthreattype,
        bitAnd(_tdthreattype, 255) AS tdthreattype,
        $LOGFIELD-tdthreatname,
        $LOGFIELD-tdwfcate,
        $LOGFIELD-tdinfoid,
        $LOGFIELD-service,
        $LOGFIELD-dstport,
        $LOGFIELD-hostname,
        normalize_url(service, hostname, coalesce($LOGFIELD_NOALIAS-url, ''), dstport, tdtype) AS tdpattern,
        ttm.name AS threattype,
        $LOGFIELD-tdthreatname,
        tnm.name AS threatname,
        wcm.name AS webcat,
        $LOGFIELD-tdscore,
        1 AS event_num
      FROM siem.ulog_sp$SPID
      LEFT JOIN siem.td_threat_type_mdata ttm ON (bitAnd(_tdthreattype,255) = ttm.id)
      LEFT JOIN siem.td_threat_name_mdata tnm ON (tdthreatname = tnm.id)
      LEFT JOIN siem.td_wf_cate_mdata wcm ON (tdwfcate = wcm.id)
      WHERE _devlogtype = 13 AND tdtype='suspicious-url'
)
GROUP BY _adomoid, dvid, timescale,
         epid, srcip, dstip, f_user, action, tdtype,
         tdthreattype, tdthreatname, tdwfcate, tdscantime,
         tdpattern, tdinfoid, threattype, threatname, webcat;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_w_pbd_ep_drilldown_hour_mv_sp$SPID
TO siem.fv_fgt_w_pbd_ep_drilldown_hour_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 3600, 0) AS timescale,
    epid, srcip, dstip, f_user, action, tdtype, tdpattern, tdinfoid,
    tdthreattype, threattype, tdthreatname, threatname, tdscantime,
    tdwfcate, webcat,
    sumState(tdscore) AS tdscore_state,
    sumState(event_num) AS event_num_state
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        epid, srcip, dstip, f_user, action, tdtype, tdpattern, tdinfoid,
        tdthreattype, threattype, tdthreatname, threatname, tdscantime,
        tdwfcate, webcat,
        sumMerge(tdscore_state) AS tdscore,
        sumMerge(event_num_state) AS event_num
      FROM siem.fv_fgt_w_pbd_ep_drilldown_5min_sp$SPID
      GROUP BY _adomoid, dvid, timescale,
               epid, srcip, dstip, f_user, action, tdtype,
               tdthreattype, tdthreatname, tdwfcate, tdscantime,
               tdpattern, tdinfoid, threattype, threatname, webcat
)
GROUP BY _adomoid, dvid, timescale,
         epid, srcip, dstip, f_user, action, tdtype,
         tdthreattype, tdthreatname, tdwfcate, tdscantime,
         tdpattern, tdinfoid, threattype, threatname, webcat;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.fv_fgt_w_pbd_ep_drilldown_day_mv_sp$SPID
TO siem.fv_fgt_w_pbd_ep_drilldown_day_sp$SPID
AS SELECT
    _adomoid, dvid,
    fv_timescale_func(timescale, 28800, 0) AS timescale,
    epid, srcip, dstip, f_user, action, tdtype, tdpattern, tdinfoid,
    tdthreattype, threattype, tdthreatname, threatname, tdscantime,
    tdwfcate, webcat,
    sumState(tdscore) AS tdscore_state,
    sumState(event_num) AS event_num_state
    FROM (
       SELECT
        _adomoid, dvid,
        timescale,
        epid, srcip, dstip, f_user, action, tdtype, tdpattern, tdinfoid,
        tdthreattype, threattype, tdthreatname, threatname, tdscantime,
        tdwfcate, webcat,
        sumMerge(tdscore_state) AS tdscore,
        sumMerge(event_num_state) AS event_num
      FROM siem.fv_fgt_w_pbd_ep_drilldown_hour_sp$SPID
      GROUP BY _adomoid, dvid, timescale,
               epid, srcip, dstip, f_user, action, tdtype,
               tdthreattype, tdthreatname, tdwfcate, tdscantime,
               tdpattern, tdinfoid, threattype, threatname, webcat
)
GROUP BY _adomoid, dvid, timescale,
         epid, srcip, dstip, f_user, action, tdtype,
         tdthreattype, tdthreatname, tdwfcate, tdscantime,
         tdpattern, tdinfoid, threattype, threatname, webcat;

ALTER TABLE siem.fv_fgt_w_pbd_ep_drilldown_day_mv_sp$SPID MODIFY COMMENT '$VERSION';
