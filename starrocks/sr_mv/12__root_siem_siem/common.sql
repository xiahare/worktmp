-- check sync mv
SHOW ALTER MATERIALIZED VIEW\G
DESC __root_siem_siem ALL;

DROP MATERIALIZED VIEW he_xl_siem_siem_5min_mv_sync_agg_states_all;
DROP MATERIALIZED VIEW __root_siem_siem_5min_mv_sync_agg_states_all;
DROP MATERIALIZED VIEW __root_siem_siem_hour_mv_sync_agg_states_all;
DROP MATERIALIZED VIEW __root_siem_siem_day_mv_sync_agg_states_all;

EXPLAIN ANALYZE
INSERT INTO __root_siem_siem (adomid,itime,id,epid,euid,data_parsername,data_sourceid,data_sourcetype,data_timestamp,logflag)
SELECT 3, DATE_ADD(NOW(), INTERVAL d hour),1,1,1,'a','a','a',now(),1
FROM table(generate_series(0, 8)) AS g(d);


SHOW PARTITIONS FROM __root_siem_siem;


ALTER MATERIALIZED VIEW __root_siem_siem_5min_mv RENAME __root_siem_siem_5min_mv_async;
ALTER MATERIALIZED VIEW __root_siem_siem_hour_mv RENAME __root_siem_siem_hour_mv_async;
ALTER MATERIALIZED VIEW __root_siem_siem_day_mv RENAME __root_siem_siem_day_mv_async;


INSERT INTO __root_siem_siem
SELECT *
FROM __root_siem_siem
limit 2;


