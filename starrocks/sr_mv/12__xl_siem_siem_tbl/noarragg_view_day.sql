drop view __xl_siem_siem_day_mv;
CREATE VIEW __xl_siem_siem_day_mv AS
SELECT
  adomid,
  mv_itime_day AS itime,
  src_ip,
  dst_ip,
  data_sourceid,
  epid,
  euid,
  data_sourcetype,
  mv_d_source_vdom AS d_source_vdom,
  event_action,
  event_id,
  event_severity,
  event_policy,
  host_name,
  mv_d_event_type AS d_event_type,
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

  -- agg merge
  mv_count_id AS logcnt,
  --mv_loguids.col1 AS loguids,
  mv_sessions AS sessions,
  mv_session_block AS session_block,

  -- net_sentbytes
  mv_sum_net_sentbytes AS net_sentbytes_sum,
  mv_min_net_sentbytes AS net_sentbytes_min,
  mv_max_net_sentbytes AS net_sentbytes_max,
  mv_sum_net_sentbytes/mv_count_id AS net_sentbytes_avg,

  -- net_recvbytes
  mv_sum_net_recvbytes AS net_recvbytes_sum,
  mv_min_net_recvbytes AS net_recvbytes_min,
  mv_max_net_recvbytes AS net_recvbytes_max,
  mv_sum_net_sentbytes/mv_count_id AS net_recvbytes_avg,

  -- net_sentpkts
  mv_sum_net_sentpkts AS net_sentpkts_sum,
  mv_min_net_sentpkts AS net_sentpkts_min,
  mv_max_net_sentpkts AS net_sentpkts_max,
  mv_sum_net_sentpkts/mv_count_id AS net_sentpkts_avg,

  -- net_rcvdpkts
  mv_sum_net_rcvdpkts AS net_rcvdpkts_sum,
  mv_min_net_rcvdpkts AS net_rcvdpkts_min,
  mv_max_net_rcvdpkts AS net_rcvdpkts_max,
  mv_sum_net_rcvdpkts/mv_count_id AS net_rcvdpkts_avg,

  -- session duration
  mv_min_net_sessionduration AS net_sessionduration_min,
  mv_max_net_sessionduration AS net_sessionduration_max,
  mv_sum_net_sessionduration as net_sessionduration_sum,
  mv_sum_net_sessionduration/mv_count_id AS net_sessionduration_avg,

  -- threat score
  mv_sum_threat_score AS threat_score_sum

FROM
  __xl_siem_siem_day_mv_sync_agg_states_all [_SYNC_MV_];
