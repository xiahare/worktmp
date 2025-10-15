/*SIEM-FV*/ select `deleted_cnt` from (
with crt_dev_lst as (
    select epid,
           host_name,
           max(user_src) as user_src,
           max(host_osfamily) as os_type,
           sum(case when threat_severity='Critical' or threat_severity='High' then 1 else 0 end) as vuln_num
    from (
        select user_src,
               max_snapshot,
               epid,
               host_name,
               host_osfamily,
               threat_id,
               threat_category,
               threat_severity,
               scan_time
        from (
            select timestamp,
                   user_src,
                   epid,
                   host_name,
                   host_osfamily,
                   threat_id,
                   threat_category,
                   threat_severity,
                   scan_time,
                   data_sourcename,
                   snapshot_time,
                   concat(data_sourcename,toString(snapshot_time)) as snapshot,
                   concat(data_sourcename,toString(max(snapshot_time) over (partition by data_sourcename))) as max_snapshot,
                   concat(data_sourcename,toString(min(snapshot_time) over (partition by data_sourcename))) as min_snapshot
            from (
                /*SIEM-FV*/
                select `adomid`,
                       `timestamp`,
                       `data_sourcename`,
                       `user_src`,
                       `epid`,
                       `host_name`,
                       `host_osfamily`,
                       `threat_id`,
                       `threat_category`,
                       `threat_severity`,
                       `severity_int`,
                       `snapshot_time`,
                       `scan_time`
                from (
                    SELECT start_time AS __start_time,
                           adomid AS `adomid`,
                           bigint1 AS `timestamp`,
                           string0 AS `data_sourcename`,
                           string1 AS `user_src`,
                           bigint2 AS `epid`,
                           string2 AS `host_name`,
                           string3 AS `host_osfamily`,
                           string4 AS `threat_id`,
                           string5 AS `threat_category`,
                           string6 AS `threat_severity`,
                           int0 AS `severity_int`,
                           timestamp0 AS `snapshot_time`,
                           timestamp1 AS `scan_time`
                    FROM __root_facet_result
                    WHERE hash_id=5075219370714182406)
                ___f_m1_5075219370714182406___
                where adomid=3
                  and ((__start_time>='2025-07-21 07:00:00' and __start_time<='2025-07-21 17:29:59'))
                UNION ALL
                select adomid as `adomid`,
                       toUInt32(toUInt32(`itime`)/1800)*1800 as timestamp,
                       data_sourcename,
                       user_src,
                       epid,
                       host_name,
                       host_osfamily,
                       threat_id,
                       threat_category,
                       threat_severity,
                       (case when threat_severity='Low' then 1 when threat_severity='Medium' then 2 when threat_severity='High' then 3 when threat_severity='Critical' then 4 else NULL end) as severity_int,
                       max(snapshot_time) as snapshot_time,
                       max(scan_time) as scan_time
                from (
                    select adomid as `adomid`,
                           toInt32(itime) as itime,
                           data_sourcename,
                           coalesce(user_name,IPv6NumToString(src_ip)) as user_src,
                           epid,
                           host_name,
                           host_osfamily,
                           (case when threat_id is not NULL and threat_severity is NULL then NULL else threat_id end) as threat_id,
                           threat_category,
                           threat_severity,
                           event_creation_time as snapshot_time,
                           event_start_time as scan_time
                    from `3_siem_siem`
                    where ((itime>='2025-07-21 17:30:00' and itime<='2025-07-21 17:59:46'))
                      and itime>='2025-07-21 07:00:00'
                      and itime<='2025-07-22 06:59:00'
                      and epid>1024
                      and event_type='event'
                      and event_subtype='endpoint-vuln'
                    order by threat_severity) t
                group by `adomid`,timestamp,data_sourcename,user_src,epid,host_name,host_osfamily,threat_id,threat_category,threat_severity,severity_int
                order by severity_int desc/*HCACHE-AGG select `adomid`, `timestamp`, `data_sourcename`, `user_src`, `epid`, `host_name`, `host_osfamily`, `threat_id`, `threat_category`, `threat_severity`, `severity_int`, max(`snapshot_time`) as `snapshot_time`, max(`scan_time`) as `scan_time` from ###LOG### group by `adomid`, `timestamp`, `data_sourcename`, `user_src`, `epid`, `host_name`, `host_osfamily`, `threat_id`, `threat_category`, `threat_severity`, `severity_int` order by `severity_int` desc AGG-END*/ ) t
            where (1=1)) t
        where max_snapshot=snapshot) t
    group by epid,host_name),
pre_dev_lst as (
    select epid,
           host_name,
           max(user_src) as user_src,
           max(host_osfamily) as os_type,
           sum(case when threat_severity='Critical' or threat_severity='High' then 1 else 0 end) as vuln_num
    from (
        select user_src,
               max_snapshot,
               epid,
               host_name,
               host_osfamily,
               threat_id,
               threat_category,
               threat_severity,
               scan_time
        from (
            select timestamp,
                   user_src,
                   epid,
                   host_name,
                   host_osfamily,
                   threat_id,
                   threat_category,
                   threat_severity,
                   scan_time,
                   data_sourcename,
                   snapshot_time,
                   concat(data_sourcename,toString(snapshot_time)) as snapshot,
                   concat(data_sourcename,toString(max(snapshot_time) over (partition by data_sourcename))) as max_snapshot,
                   concat(data_sourcename,toString(min(snapshot_time) over (partition by data_sourcename))) as min_snapshot
            from (
                /*SIEM-FV*/
                select `adomid`,
                       `timestamp`,
                       `data_sourcename`,
                       `user_src`,
                       `epid`,
                       `host_name`,
                       `host_osfamily`,
                       `threat_id`,
                       `threat_category`,
                       `threat_severity`,
                       `severity_int`,
                       `snapshot_time`,
                       `scan_time`
                from (
                    SELECT start_time AS __start_time,
                           adomid AS `adomid`,
                           bigint1 AS `timestamp`,
                           string0 AS `data_sourcename`,
                           string1 AS `user_src`,
                           bigint2 AS `epid`,
                           string2 AS `host_name`,
                           string3 AS `host_osfamily`,
                           string4 AS `threat_id`,
                           string5 AS `threat_category`,
                           string6 AS `threat_severity`,
                           int0 AS `severity_int`,
                           timestamp0 AS `snapshot_time`,
                           timestamp1 AS `scan_time`
                    FROM __root_facet_result
                    WHERE hash_id=5075219370714182406) ___f_m1_5075219370714182406___
                where adomid=3
                  and ((__start_time>='2025-07-21 07:00:00' and __start_time<='2025-07-21 17:29:59'))
                UNION ALL
                select adomid as `adomid`,
                       toUInt32(toUInt32(`itime`)/1800)*1800 as timestamp,
                       data_sourcename,
                       user_src,
                       epid,
                       host_name,
                       host_osfamily,
                       threat_id,
                       threat_category,
                       threat_severity,
                       (case when threat_severity='Low' then 1 when threat_severity='Medium' then 2 when threat_severity='High' then 3 when threat_severity='Critical' then 4 else NULL end) as severity_int,
                       max(snapshot_time) as snapshot_time,
                       max(scan_time) as scan_time
                from (
                    select adomid as `adomid`,
                           toInt32(itime) as itime,
                           data_sourcename,
                           coalesce(user_name,IPv6NumToString(src_ip)) as user_src,
                           epid,
                           host_name,
                           host_osfamily,
                           (case when threat_id is not NULL and threat_severity is NULL then NULL else threat_id end) as threat_id,
                           threat_category,
                           threat_severity,
                           event_creation_time as snapshot_time,
                           event_start_time as scan_time
                    from `3_siem_siem`
                    where ((itime>='2025-07-21 17:30:00' and itime<='2025-07-21 17:59:46'))
                      and itime>='2025-07-21 07:00:00'
                      and itime<='2025-07-22 06:59:00'
                      and epid>1024
                      and event_type='event'
                      and event_subtype='endpoint-vuln'
                    order by threat_severity) t
                group by `adomid`,timestamp,data_sourcename,user_src,epid,host_name,host_osfamily,threat_id,threat_category,threat_severity,severity_int
                order by severity_int desc/*HCACHE-AGG select `adomid`, `timestamp`, `data_sourcename`, `user_src`, `epid`, `host_name`, `host_osfamily`, `threat_id`, `threat_category`, `threat_severity`, `severity_int`, max(`snapshot_time`) as `snapshot_time`, max(`scan_time`) as `scan_time` from ###LOG### group by `adomid`, `timestamp`, `data_sourcename`, `user_src`, `epid`, `host_name`, `host_osfamily`, `threat_id`, `threat_category`, `threat_severity`, `severity_int` order by `severity_int` desc AGG-END*/ ) t
            where (1=1)) t
        where max_snapshot=snapshot) t
    group by epid,host_name)
select sum(added_cnt) as added_cnt,
       sum(deleted_cnt) as deleted_cnt
from ((select count(distinct epid) as added_cnt, 0 as deleted_cnt from crt_dev_lst t1 where epid not in (select epid from pre_dev_lst t2))
      union all
      (select 0 as added_cnt, count(distinct epid) as deleted_cnt from pre_dev_lst t1 where epid not in (select epid from crt_dev_lst t2))) t
LIMIT 10000000) t
limit 1;
