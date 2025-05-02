select * from (select * from (select dst_ip,count(*) from siem.__priv_alladom where itime >= 0 group by dst_ip )) t limit 0;

/*SIEM-FV*/select * from ###(select dst_ip,count(*) from $log where $filter group by dst_ip )###


select * from (/*SIEM-FV*/select * from (select dst_ip,count(*) from siem.__priv_alladom where itime >= 0 group by dst_ip )) t limit 0;


create database siem ON CLUSTER 'default';

CREATE VIEW IF NOT EXISTS siem.__priv_alladom 
ON CLUSTER 'default'
AS
SELECT adomid as adom_oid,*
FROM db_log_public.__root_siem_siem_view
;
CREATE VIEW IF NOT EXISTS siem.__priv_adom3 
ON CLUSTER 'default'
AS
SELECT *
FROM siem.__priv_alladom 
where adomid=3
;


use siem;
show tables;

DROP VIEW IF EXISTS siem.__priv_alladom ON CLUSTER 'default';
DROP VIEW IF EXISTS siem.__priv_adom3 ON CLUSTER 'default';



kubectl exec -it -n db ch-clickhouse-shard0-1 -- clickhouse client  -m -n -u admin --password `kubectl get secret -n db ch-clickhouse --template='{{index .data "admin-password"}}' | base64 --decode | awk '{print $1;}' | tr -d '\n'`

clickhouse-client --password $(cat /etc/clickhouse-security)

select * from (select * from (select dst_ip,count(*) from siem.__priv_alladom where itime >= 0 group by dst_ip )) t limit 0;





bad SQL grammar [/*SIEM-FV*/select * from (select dst_ip,count(*) from (SELECT * FROM siem.__priv_adom3 SAMPLE 1000000 UNION ALL SELECT * FROM siem.__priv_alladom SAMPLE 1000000 WHERE adom_oid=3) t10 where itime >= 1741935600 and itime <= 1742540399 group by dst_ip )]; nested exception is java.sql.BatchUpdateException: Code: 60. DB::Exception: Table siem.__priv_adom3 doesn't exist. (UNKNOWN_TABLE) (version 23.5.4.25 (official build))