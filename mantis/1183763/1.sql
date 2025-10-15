SELECT deleted_cnt
FROM (
    WITH
    crt_dev_lst AS (
        SELECT
            epid,
            host_name,
            MAX(user_src) AS user_src,
            MAX(host_osfamily) AS os_type,
            SUM(CASE WHEN threat_severity = 'Critical' OR threat_severity = 'High' THEN 1 ELSE 0 END) AS vuln_num
        FROM (
            SELECT
                user_src,
                max_snapshot,
                epid,
                host_name,
                host_osfamily,
                threat_id,
                threat_category,
                threat_severity,
                scan_time
            FROM (
                SELECT
                    timestamp,
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
                    CONCAT(data_sourcename, toString(snapshot_time)) AS snapshot,
                    CONCAT(data_sourcename, toString(MAX(snapshot_time) OVER (PARTITION BY data_sourcename))) AS max_snapshot,
                    CONCAT(data_sourcename, toString(MIN(snapshot_time) OVER (PARTITION BY data_sourcename))) AS min_snapshot
                FROM (
                    /* SIEM-FV */
                    SELECT
                        adomid,
                        timestamp,
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
                            adomid AS adomid,
                            bigint1 AS timestamp,
                            string0 AS data_sourcename,
                            string1 AS user_src,
                            bigint2 AS epid,
                            string2 AS host_name,
                            string3 AS host_osfamily,
                            string4 AS threat_id,
                            string5 AS threat_category,
                            string6 AS threat_severity,
                            int0 AS severity_int,
                            timestamp0 AS snapshot_time,
                            timestamp1 AS scan_time
                        FROM __root_facet_result
                        WHERE hash_id = 5075219370714182406
                    ) ___f_m1_5075219370714182406___
                    WHERE adomid = 3
                      AND (__start_time >= '2025-07-21 07:00:00' AND __start_time <= '2025-07-21 17:29:59')

                    UNION ALL

                    SELECT
                        adomid,
                        toUInt32(toUInt32(itime) / 1800) * 1800 AS timestamp,
                        data_sourcename,
                        user_src,
                        epid,
                        host_name,
                        host_osfamily,
                        threat_id,
                        threat_category,
                        threat_severity,
                        CASE
                            WHEN threat_severity = 'Low' THEN 1
                            WHEN threat_severity = 'Medium' THEN 2
                            WHEN threat_severity = 'High' THEN 3
                            WHEN threat_severity = 'Critical' THEN 4
                            ELSE NULL
                        END AS severity_int,
                        MAX(snapshot_time) AS snapshot_time,
                        MAX(scan_time) AS scan_time
                    FROM (
                        SELECT
                            adomid,
                            toInt32(itime) AS itime,
                            data_sourcename,
                            COALESCE(user_name, IPv6NumToString(src_ip)) AS user_src,
                            epid,
                            host_name,
                            host_osfamily,
                            CASE WHEN threat_id IS NOT NULL AND threat_severity IS NULL THEN NULL ELSE threat_id END AS threat_id,
                            threat_category,
                            threat_severity,
                            event_creation_time AS snapshot_time,
                            event_start_time AS scan_time
                        FROM 3_siem_siem
                        WHERE itime BETWEEN '2025-07-21 07:00:00' AND '2025-07-22 06:59:00'
                          AND itime >= '2025-07-21 17:30:00' AND itime <= '2025-07-21 17:59:46'
                          AND epid > 1024
                          AND event_type = 'event'
                          AND event_subtype = 'endpoint-vuln'
                        ORDER BY threat_severity
                    ) t
                    GROUP BY
                        adomid,
                        timestamp,
                        data_sourcename,
                        user_src,
                        epid,
                        host_name,
                        host_osfamily,
                        threat_id,
                        threat_category,
                        threat_severity,
                        severity_int
                    ORDER BY severity_int DESC
                )
                WHERE max_snapshot = snapshot
            )
        )
        GROUP BY epid, host_name
    ),
    
    pre_dev_lst AS (
        SELECT
            epid,
            host_name,
            MAX(user_src) AS user_src,
            MAX(host_osfamily) AS os_type,
            SUM(CASE WHEN threat_severity = 'Critical' OR threat_severity = 'High' THEN 1 ELSE 0 END) AS vuln_num
        FROM (
            SELECT
                user_src,
                max_snapshot,
                epid,
                host_name,
                host_osfamily,
                threat_id,
                threat_category,
                threat_severity,
                scan_time
            FROM (
                SELECT
                    timestamp,
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
                    CONCAT(data_sourcename, toString(snapshot_time)) AS snapshot,
                    CONCAT(data_sourcename, toString(MAX(snapshot_time) OVER (PARTITION BY data_sourcename))) AS max_snapshot,
                    CONCAT(data_sourcename, toString(MIN(snapshot_time) OVER (PARTITION BY data_sourcename))) AS min_snapshot
                FROM (
                    /* SIEM-FV */
                    SELECT
                        adomid,
                        timestamp,
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
                            bigint1 AS timestamp,
                            string0 AS data_sourcename,
                            string1 AS user_src,
                            bigint2 AS epid,
                            string2 AS host_name,
                            string3 AS host_osfamily,
                            string4 AS threat_id,
                            string5 AS threat_category,
                            string6 AS threat_severity,
                            int0 AS severity_int,
                            timestamp0 AS snapshot_time,
                            timestamp1 AS scan_time
                        FROM __root_facet_result
                        WHERE hash_id = 5075219370714182406
                    ) ___f_m1_5075219370714182406___
                    WHERE adomid = 3
                      AND (__start_time >= '2025-07-21 07:00:00' AND __start_time <= '2025-07-21 17:29:59')

                    UNION ALL

                    SELECT
                        adomid,
                        toUInt32(toUInt32(itime) / 1800) * 1800 AS timestamp,
                        data_sourcename,
                        user_src,
                        epid,
                        host_name,
                        host_osfamily,
                        threat_id,
                        threat_category,
                        threat_severity,
                        CASE
                            WHEN threat_severity = 'Low' THEN 1
                            WHEN threat_severity = 'Medium' THEN 2
                            WHEN threat_severity = 'High' THEN 3
                            WHEN threat_severity = 'Critical' THEN 4
                            ELSE NULL
                        END AS severity_int,
                        MAX(snapshot_time) AS snapshot_time,
                        MAX(scan_time) AS scan_time
                    FROM (
                        SELECT
                            adomid,
                            toInt32(itime) AS itime,
                            data_sourcename,
                            COALESCE(user_name, IPv6NumToString(src_ip)) AS user_src,
                            epid,
                            host_name,
                            host_osfamily,
                            CASE WHEN threat_id IS NOT NULL AND threat_severity IS NULL THEN NULL ELSE threat_id END AS threat_id,
                            threat_category,
                            threat_severity,
                            event_creation_time AS snapshot_time,
                            event_start_time AS scan_time
                        FROM 3_siem_siem
                        WHERE itime BETWEEN '2025-07-21 07:00:00' AND '2025-07-22 06:59:00'
                          AND itime >= '2025-07-21 17:30:00' AND itime <= '2025-07-21 17:59:46'
                          AND epid > 1024
                          AND event_type = 'event'
                          AND event_subtype = 'endpoint-vuln'
                        ORDER BY threat_severity
                    ) t
                    GROUP BY
                        adomid,
                        timestamp,
                        data_sourcename,
                        user_src,
                        epid,
                        host_name,
                        host_osfamily,
                        threat_id,
                        threat_category,
                        threat_severity,
                        severity_int
                    ORDER BY severity_int DESC
                )
                WHERE max_snapshot = snapshot
            )
        )
        GROUP BY epid, host_name
    )

    SELECT
        SUM(added_cnt) AS added_cnt,
        SUM(deleted_cnt) AS deleted_cnt
    FROM (
        SELECT
            COUNT(DISTINCT epid) AS added_cnt,
            toUInt64(0) AS deleted_cnt
        FROM crt_dev_lst t1
        WHERE epid NOT IN (SELECT epid FROM pre_dev_lst t2)

        UNION ALL

        SELECT
            toUInt64(0) AS added_cnt,
            COUNT(DISTINCT epid) AS deleted_cnt
        FROM pre_dev_lst t1
        WHERE epid NOT IN (SELECT epid FROM crt_dev_lst t2)
    ) t
    LIMIT 10000000
) t
LIMIT 1;