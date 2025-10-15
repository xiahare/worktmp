DROP MATERIALIZED VIEW IF EXISTS __xl_siem_siem_hour_mv_sync_agg_states_all;
CREATE MATERIALIZED VIEW IF NOT EXISTS __xl_siem_siem_hour_mv_sync_agg_states_all AS
SELECT
    adomid,
    time_slice(`itime`, INTERVAL 1 hour, floor) AS itime_hour,
    src_ip,
    dst_ip,
    data_sourceid,
    epid,
    euid,
    data_sourcetype,
    COALESCE(SPLIT(' ', COALESCE(`data_sourcename`, ''))[-1], 'root') AS d_source_vdom,
    event_action,
    event_id,
    event_severity,
    event_policy,
    host_name,
    IF(`event_type` IN ('utm'), `event_subtype`, `event_type`) AS d_event_type,
    event_cat,
    dst_domain,
    http_referer,
    app_name,
    app_cat,
    app_proc,
    app_service,
    file_name,
    file_hash,
    threat_name,
    threat_type,
    threat_action,
    threat_pattern,

    -- merge columns
    COUNT(id) AS logcnt,
    array_agg_union(array_agg_state(`id`)) AS loguids,

    SUM(CAST((IF((`logflag` & 1) > 0, 1, 0)) AS BIGINT)) AS sessions,
    SUM(CAST((IF((`logflag` & 2) > 0, 1, 0)) AS BIGINT)) AS session_block,

    SUM(net_sentbytes) AS net_sentbytes_sum,
    MIN(net_sentbytes) AS net_sentbytes_min,
    MAX(net_sentbytes) AS net_sentbytes_max,

    SUM(net_recvbytes) AS net_recvbytes_sum,
    MIN(net_recvbytes) AS net_recvbytes_min,
    MAX(net_recvbytes) AS net_recvbytes_max,

    SUM(net_sentpkts) AS net_sentpkts_sum,
    MIN(net_sentpkts) AS net_sentpkts_min,
    MAX(net_sentpkts) AS net_sentpkts_max,

    SUM(net_rcvdpkts) AS net_rcvdpkts_sum,
    MIN(net_rcvdpkts) AS net_rcvdpkts_min,
    MAX(net_rcvdpkts) AS net_rcvdpkts_max,

    MIN(net_sessionduration) AS net_sessionduration_min,
    MAX(net_sessionduration) AS net_sessionduration_max,
    SUM(net_sessionduration) AS net_sessionduration_sum,

    SUM(threat_score) AS threat_score_sum

FROM
    __xl_siem_siem_tbl
GROUP BY
    adomid,
    time_slice(`itime`, INTERVAL 1 hour, floor),
    src_ip,
    dst_ip,
    data_sourceid,
    epid,
    euid,
    data_sourcetype,
    d_source_vdom,
    event_action,
    event_id,
    event_severity,
    event_policy,
    host_name,
    d_event_type,
    event_cat,
    dst_domain,
    http_referer,
    app_name,
    app_cat,
    app_proc,
    app_service,
    file_name,
    file_hash,
    threat_name,
    threat_type,
    threat_action,
    threat_pattern;
