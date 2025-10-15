SELECT *
FROM (
    SELECT
        sender,
        SUM(total_num) AS total_message,
        SUM(COALESCE(message_length, 0)) AS total_size,
        SUM(CASE WHEN virus IS NOT NULL THEN total_num ELSE 0 END) AS total_malware,
        SUM(CASE WHEN classifier = 'FortiGuard Phishing' THEN total_num ELSE 0 END) AS total_phishing,
        SUM(CASE WHEN category = 'VIRUS' THEN total_num ELSE 0 END) AS total_virus,
        SUM(CASE WHEN category = 'SPAM' THEN total_num ELSE 0 END) AS total_spam
    FROM (
        SELECT *,
            CASE
                WHEN classifier IN (
                    'Not Spam', 'User Safe', 'System Safe', 'FortiGuard AntiSpam-Safe',
                    'Quarantine Control', 'Bypass Scan On Auth', 'Disclaimer', 'Defer Delivery',
                    'Session Safe', 'Safelist Word', 'Domain Safe', 'TLS Enforcement',
                    'Message Cryptography', 'Delivery Control', 'Encrypted Content',
                    'Content Encryption', 'Access Control-Safe-Relay', 'TLS Session',
                    'Policy Match', 'Dynamic Safe List', 'DLP Encryption', 'Access Control-Safe',
                    'Session Profile', 'SPF Check'
                ) THEN 'NOT SPAM'
                WHEN classifier IN (
                    'Virus Signature', 'File Signature', 'FortiSandbox File', 'Malware Outbreak',
                    'Virus Outbreak', 'FortiSandbox URL', 'FortiSandbox NoResult'
                ) THEN 'VIRUS'
                ELSE 'SPAM'
            END AS category
        FROM (
            SELECT *
            FROM (
                SELECT
                    adomid, devid, vd, timescale, sender, recipient,
                    classifier, virus, direction, message_length,
                    scan_time, xfer_time, total_num
                FROM (
                    SELECT
                        start_time AS __start_time,
                        adomid,
                        string0 AS devid,
                        string1 AS vd,
                        bigint1 AS timescale,
                        string2 AS sender,
                        string3 AS recipient,
                        string4 AS classifier,
                        string5 AS virus,
                        string6 AS direction,
                        bigint2 AS message_length,
                        double0 AS scan_time,
                        double1 AS xfer_time,
                        bigint3 * 1 AS total_num
                    FROM __root_facet_result
                    WHERE hash_id = 6991099452759078130
                ) AS ___f_m1_6991099452759078130___
                WHERE adomid = 3
                  AND (__start_time >= '2025-05-14 04:00:00'
                       AND __start_time <= '2025-05-14 04:39:59')
                UNION ALL
                /*tag:fv_fml_h_stats*/
                SELECT
                    adomid, devid, vd, agg_timescale AS timescale,
                    sender, recipient, classifier, virus, direction,
                    message_length, scan_time, xfer_time, total_num
                FROM (
                    SELECT *,
                        ROW_NUMBER() OVER (
                            PARTITION BY adomid, devid, vd, agg_timescale
                            ORDER BY total_num DESC
                        ) AS count_rank
                    FROM (
                        SELECT
                            adomid, devid, vd,
                            fv_timescale_func(CAST(itime AS bigint), 86400, 0) AS agg_timescale,
                            `from` AS sender,
                            `to` AS recipient,
                            classifier, virus, direction,
                            SUM(COALESCE(message_length, 0)) AS message_length,
                            SUM(COALESCE(scan_time, 0)) AS scan_time,
                            SUM(COALESCE(xfer_time, 0)) AS xfer_time,
                            COUNT(*) AS total_num
                        FROM 3_fml_history
                        WHERE (
                                (itime >= '2025-05-09 05:35:33' AND itime <= '2025-05-14 03:59:59')
                            )
                          AND itime >= '2025-05-07 04:49:00'
                          AND itime <= '2025-05-14 04:49:00'
                        GROUP BY
                            adomid, devid, vd, agg_timescale,
                            sender, recipient, classifier, virus, direction
                    ) AS agg_query
                ) AS rank_query
                /*SkipSTART*/ ORDER BY count_rank /*SkipEND*/
            ) AS t
            WHERE category = 'SPAM'
              AND 1 = 1
        ) AS t
    ) AS t
    WHERE sender IS NOT NULL
    GROUP BY sender
    ORDER BY total_spam DESC
    LIMIT 10
) AS t;