-- Filename: 2.sql
-- Description: fixed version that eliminates window-function-in-WHERE error

WITH
/* -------------------------------------------------------------------
   1. 统一并清洗原始数据到 raw_events
   -------------------------------------------------------------------*/
raw_events AS (
    -- 来自 __root_facet_result -------------------------------------------------
    SELECT
        adomid,
        timestamp                                   AS ts,              -- Int64
        data_sourcename,
        user_src,
        epid,
        host_name,
        host_osfamily,
        threat_id,
        threat_category,
        threat_severity,
        severity_int,
        snapshot_time,
        scan_time
    FROM (
        SELECT
            start_time AS __start_time,
            adomid,
            bigint1    AS timestamp,
            string0    AS data_sourcename,
            string1    AS user_src,
            bigint2    AS epid,
            string2    AS host_name,
            string3    AS host_osfamily,
            string4    AS threat_id,
            string5    AS threat_category,
            string6    AS threat_severity,
            int0       AS severity_int,
            timestamp0 AS snapshot_time,
            timestamp1 AS scan_time
        FROM __root_facet_result
        WHERE hash_id = 5075219370714182406
    ) facet
    WHERE adomid = 3
      AND __start_time BETWEEN '2025-07-21 07:00:00' AND '2025-07-21 17:29:59'

    UNION ALL

    -- 来自 3_siem_siem ---------------------------------------------------------
    SELECT
        adomid,
        toInt64(toUInt32(itime) / 1800) * 1800     AS ts,               -- 显式 Int64
        data_sourcename,
        user_src,
        epid,
        host_name,
        host_osfamily,
        threat_id,
        threat_category,
        threat_severity,
        multiIf(threat_severity = 'Low', 1,
                threat_severity = 'Medium', 2,
                threat_severity = 'High', 3,
                threat_severity = 'Critical', 4,
                NULL)                              AS severity_int,
        max(snapshot_time) AS snapshot_time,
        max(scan_time)     AS scan_time
    FROM (
        SELECT
            adomid,
            toInt32(itime) AS itime,
            data_sourcename,
            coalesce(user_name, IPv6NumToString(src_ip)) AS user_src,
            epid,
            host_name,
            host_osfamily,
            multiIf(threat_id IS NOT NULL AND threat_severity IS NULL, NULL, threat_id) AS threat_id,
            threat_category,
            threat_severity,
            event_creation_time AS snapshot_time,
            event_start_time    AS scan_time
        FROM `3_siem_siem`
        WHERE itime BETWEEN '2025-07-21 07:00:00' AND '2025-07-22 06:59:00'
          AND itime BETWEEN '2025-07-21 17:30:00' AND '2025-07-21 17:59:46'
          AND epid > 1024
          AND event_type   = 'event'
          AND event_subtype= 'endpoint-vuln'
    ) ev
    GROUP BY
        adomid,
        ts,
        data_sourcename,
        user_src,
        epid,
        host_name,
        host_osfamily,
        threat_id,
        threat_category,
        threat_severity,
        severity_int
),
/* -------------------------------------------------------------------
   2. 计算快照标识 & 窗口函数 (仅在此层使用)
   -------------------------------------------------------------------*/
snapshots AS (
    SELECT
        *,
        concat(data_sourcename, toString(snapshot_time))                                      AS snapshot_id,
        concat(data_sourcename, toString(max(snapshot_time) OVER (PARTITION BY data_sourcename))) AS max_snapshot_id,
        concat(data_sourcename, toString(min(snapshot_time) OVER (PARTITION BY data_sourcename))) AS min_snapshot_id
    FROM raw_events
),
/* 当前与之前快照 */
crt_base AS (
    SELECT * FROM snapshots WHERE snapshot_id = max_snapshot_id
),
pre_base AS (
    SELECT * FROM snapshots WHERE snapshot_id = min_snapshot_id
),
/* -------------------------------------------------------------------
   3. 设备维度聚合 (当前 / 之前)
   -------------------------------------------------------------------*/
crt_dev_lst AS (
    SELECT
        epid,
        host_name,
        max(user_src)      AS user_src,
        max(host_osfamily) AS os_type,
        sum(multiIf(threat_severity IN ('Critical','High'), 1, 0)) AS vuln_num
    FROM crt_base
    GROUP BY epid, host_name
),
pre_dev_lst AS (
    SELECT
        epid,
        host_name,
        max(user_src)      AS user_src,
        max(host_osfamily) AS os_type,
        sum(multiIf(threat_severity IN ('Critical','High'), 1, 0)) AS vuln_num
    FROM pre_base
    GROUP BY epid, host_name
)
/* -------------------------------------------------------------------
   4. 计算新增 / 删除设备
   -------------------------------------------------------------------*/
SELECT
    sum(added_cnt)   AS added_cnt,
    sum(deleted_cnt) AS deleted_cnt
FROM (
    /* 新增 */
    SELECT
        countDistinct(epid) AS added_cnt,
        toUInt64(0)        AS deleted_cnt
    FROM crt_dev_lst
    WHERE epid NOT IN (SELECT epid FROM pre_dev_lst)

    UNION ALL

    /* 删除 */
    SELECT
        toUInt64(0)        AS added_cnt,
        countDistinct(epid) AS deleted_cnt
    FROM pre_dev_lst
    WHERE epid NOT IN (SELECT epid FROM crt_dev_lst)
) t;
