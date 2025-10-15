-- check sync mv
SHOW ALTER MATERIALIZED VIEW\G
DESC __xl_siem_siem_tbl ALL;


-- DROP 
DROP MATERIALIZED VIEW __xl_siem_siem_5min_mv_sync_agg_states_all;
DROP MATERIALIZED VIEW __xl_siem_siem_hour_mv_sync_agg_states_all;
DROP MATERIALIZED VIEW __xl_siem_siem_day_mv_sync_agg_states_all;

INSERT INTO __xl_siem_siem_tbl
SELECT *
FROM __root_siem_siem
limit 2;

INSERT INTO __xl_siem_siem_tbl
SELECT *
FROM __xl_siem_siem_tbl
limit 2;

SELECT count(*) from __xl_siem_siem_tbl;
SELECT count(*) from __xl_siem_siem_5min_mv;
SELECT count(*) from __xl_siem_siem_hour_mv;
SELECT count(*) from __xl_siem_siem_day_mv;

EXPLAIN ANALYZE
INSERT INTO __xl_siem_siem_tbl (adomid,itime,id,epid,euid,data_parsername,data_sourceid,data_sourcetype,data_timestamp,logflag)
SELECT 3, DATE_ADD(NOW(), INTERVAL d hour),1,1,1,'a','a','a',now(),1
FROM table(generate_series(0, 8)) AS g(d);
