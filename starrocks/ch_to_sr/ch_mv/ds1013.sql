SELECT itime,
       devid,
       adomid,
       id as loguid,
       devlogtype,
       epid,
       euid,
       dstepid,
       dsteuid,
       srcip,
       dstip,
       application as app,
       f_user,
       avatar,
       JSONExtractString(match_result, 'keywords') as keywords,
       JSONExtractString(match_result, 'category') as category,
       host_name,
       inspected_data
       FROM (
           SELECT
               itime,
               devid,
               adomid,
               id,
               0 AS devlogtype,
               epid,
               euid,
               dstepid,
               dsteuid,
               dstip,
               srcip,
               (CASE WHEN fctuid IS NOT NULL AND unauthuser IS NOT NULL THEN CONCAT(toString(fctuid), ',', unauthuser) ELSE NULL END) AS avatar,
               coalesce(nullifna(user), nullifna(unauthuser), ipstr(srcip)) AS f_user,
               app as application,
               hostname as host_name,
               filename AS inspected_data,
               safeguardMatchDetail(filename) AS match_result
          FROM __${var:storage_id}_fgt_app_ctrl
          WHERE ${var:itime_range} and filename IS NOT NULL and not empty(match_result)
          UNION ALL
           SELECT
               itime,
               devid,
               adomid,
               id,
               4 AS devlogtype,
               epid,
               euid,
               dstepid,
               dsteuid,
               dstip,
               srcip,
               (CASE WHEN fctuid IS NOT NULL AND unauthuser IS NOT NULL THEN CONCAT(toString(fctuid), ',', unauthuser) ELSE NULL END) AS avatar,
               coalesce(nullifna(user), nullifna(unauthuser), ipstr(srcip)) AS f_user,
               service as application,
               NULL as host_name,
               subject AS inspected_data,
               safeguardMatchDetail(subject) AS match_result
          FROM __${var:storage_id}_fgt_emailfilter
          WHERE ${var:itime_range} and subject IS NOT NULL and not empty(match_result)
          UNION ALL
           SELECT
               itime,
               devid,
               adomid,
               id,
               13 AS devlogtype,
               epid,
               euid,
               dstepid,
               dsteuid,
               dstip,
               srcip,
               (CASE WHEN fctuid IS NOT NULL AND unauthuser IS NOT NULL THEN CONCAT(toString(fctuid), ',', unauthuser) ELSE NULL END) AS avatar,
               coalesce(nullifna(user), nullifna(unauthuser), ipstr(srcip)) AS f_user,
               service as application,
               hostname as host_name,
               keyword AS inspected_data,
               safeguardMatchDetail(keyword) AS match_result
          FROM __${var:storage_id}_fgt_webfilter
          WHERE ${var:itime_range} and keyword IS NOT NULL and not empty(match_result)

        ) ds_fgt_u_safeguard_match_mv