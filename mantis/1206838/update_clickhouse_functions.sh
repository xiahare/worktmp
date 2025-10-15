#!/bin/bash
# ==============================================
# Script to drop and create ClickHouse functions
# on the 'default' cluster
# ==============================================

# Configuration
KUBECONFIG="/root/.kube/config"
NAMESPACE="db"
DATABASE_NAME="db_log_public"
CLUSTER_NAME="default"
POD_LABEL="app.kubernetes.io/component=clickhouse"

# Get any ClickHouse pod name in the cluster
POD_NAME=$(kubectl --kubeconfig="$KUBECONFIG" -n "$NAMESPACE" get pods -l "$POD_LABEL" --no-headers -o custom-columns=":metadata.name" | head -n1)
CLICKHOUSE_ADMIN_PASSWORD=$(kubectl get secret -n db ch-clickhouse --template='{{index .data "admin-password"}}' | base64 --decode | awk '{print $1;}' | tr -d '\n')

if [ -z "$POD_NAME" ]; then
    echo "Error: No ClickHouse pod found in namespace $NAMESPACE with label $POD_LABEL"
    exit 1
fi

# ================================
# SQL string containing all drops and creates
# ================================
SQL=$(cat <<'EOF'
-- Drop existing functions
DROP FUNCTION IF EXISTS is_fgt_6k7k ON CLUSTER default;
DROP FUNCTION IF EXISTS get_fgt_role ON CLUSTER default;
DROP FUNCTION IF EXISTS match_question ON CLUSTER default;
DROP FUNCTION IF EXISTS match_path ON CLUSTER default;
DROP FUNCTION IF EXISTS remove_trailing ON CLUSTER default;
DROP FUNCTION IF EXISTS remove_host_prefix ON CLUSTER default;
DROP FUNCTION IF EXISTS is_host_prefix ON CLUSTER default;
DROP FUNCTION IF EXISTS massage_path ON CLUSTER default;
DROP FUNCTION IF EXISTS finalize_path ON CLUSTER default;
DROP FUNCTION IF EXISTS add_port ON CLUSTER default;
DROP FUNCTION IF EXISTS normalize_url ON CLUSTER default;
DROP FUNCTION IF EXISTS event_level_i2s ON CLUSTER default;
DROP FUNCTION IF EXISTS event_level_s2i ON CLUSTER default;
DROP FUNCTION IF EXISTS ts_itime ON CLUSTER default;
DROP FUNCTION IF EXISTS ts_dtime ON CLUSTER default;
DROP FUNCTION IF EXISTS from_itime ON CLUSTER default;
DROP FUNCTION IF EXISTS from_dtime ON CLUSTER default;
DROP FUNCTION IF EXISTS nanosecond_to_sec ON CLUSTER default;
DROP FUNCTION IF EXISTS nanosec_to_sec ON CLUSTER default;
DROP FUNCTION IF EXISTS file_name_ext ON CLUSTER default;
DROP FUNCTION IF EXISTS threat_level_i2s ON CLUSTER default;
DROP FUNCTION IF EXISTS threat_level_s2i ON CLUSTER default;
DROP FUNCTION IF EXISTS get_devtype ON CLUSTER default;
DROP FUNCTION IF EXISTS nullifna ON CLUSTER default;
DROP FUNCTION IF EXISTS app_group_name ON CLUSTER default;
DROP FUNCTION IF EXISTS is_ip ON CLUSTER default;
DROP FUNCTION IF EXISTS double_position ON CLUSTER default;
DROP FUNCTION IF EXISTS root_domain ON CLUSTER default;
DROP FUNCTION IF EXISTS threatweight_level_sum ON CLUSTER default;
DROP FUNCTION IF EXISTS threatweight_sum ON CLUSTER default;
DROP FUNCTION IF EXISTS threatlevel_max ON CLUSTER default;
DROP FUNCTION IF EXISTS fv_timescale_func ON CLUSTER default;
DROP FUNCTION IF EXISTS vpn_trim ON CLUSTER default;
DROP FUNCTION IF EXISTS devvd_str ON CLUSTER default;
DROP FUNCTION IF EXISTS coalesce_str ON CLUSTER default;
DROP FUNCTION IF EXISTS coalesce_str3 ON CLUSTER default;
DROP FUNCTION IF EXISTS coalesce_str4 ON CLUSTER default;
DROP FUNCTION IF EXISTS logid_to_int ON CLUSTER default;
DROP FUNCTION IF EXISTS convert_unit ON CLUSTER default;
DROP FUNCTION IF EXISTS convert_unit_to_number ON CLUSTER default;
DROP FUNCTION IF EXISTS convert_unit_to_num ON CLUSTER default;
DROP FUNCTION IF EXISTS safeToFloat32 ON CLUSTER default;
DROP FUNCTION IF EXISTS string_to_num ON CLUSTER default;
DROP FUNCTION IF EXISTS isIPv4 ON CLUSTER default;
DROP FUNCTION IF EXISTS is_Zero_IPv6 ON CLUSTER default;
DROP FUNCTION IF EXISTS ip_subnet ON CLUSTER default;
DROP FUNCTION IF EXISTS ip_subnet_contains ON CLUSTER default;
DROP FUNCTION IF EXISTS faz_func_version ON CLUSTER default;
DROP FUNCTION IF EXISTS os2index ON CLUSTER default;
DROP FUNCTION IF EXISTS index2Os ON CLUSTER default;
DROP FUNCTION IF EXISTS fctos_to_devtype ON CLUSTER default;
DROP FUNCTION IF EXISTS format_numeric_no_decimal ON CLUSTER default;
DROP FUNCTION IF EXISTS format_numeric ON CLUSTER default;
DROP FUNCTION IF EXISTS safe_divide ON CLUSTER default;
DROP FUNCTION IF EXISTS safer_divide ON CLUSTER default;
DROP FUNCTION IF EXISTS split_part ON CLUSTER default;
DROP FUNCTION IF EXISTS fct_webcat ON CLUSTER default;
DROP FUNCTION IF EXISTS severity_i2s ON CLUSTER default;
DROP FUNCTION IF EXISTS severity_s2i ON CLUSTER default;
DROP FUNCTION IF EXISTS bandwidth_unit ON CLUSTER default;
DROP FUNCTION IF EXISTS ipstr ON CLUSTER default;
DROP FUNCTION IF EXISTS host ON CLUSTER default;
DROP FUNCTION IF EXISTS virusid_to_str ON CLUSTER default;
DROP FUNCTION IF EXISTS inc_cat_encode ON CLUSTER default;
DROP FUNCTION IF EXISTS strpos ON CLUSTER default;
DROP FUNCTION IF EXISTS incid_to_str ON CLUSTER default;
DROP FUNCTION IF EXISTS btrim ON CLUSTER default;
DROP FUNCTION IF EXISTS generate_series ON CLUSTER default;
DROP FUNCTION IF EXISTS string_position ON CLUSTER default;
DROP FUNCTION IF EXISTS extract_epoch ON CLUSTER default;
DROP FUNCTION IF EXISTS extract_epoch_from_timestr ON CLUSTER default;
DROP FUNCTION IF EXISTS email_domain ON CLUSTER default;
DROP FUNCTION IF EXISTS email_user ON CLUSTER default;
DROP FUNCTION IF EXISTS safeValue ON CLUSTER default;
DROP FUNCTION IF EXISTS safeToDecimalStr ON CLUSTER default;
DROP FUNCTION IF EXISTS IPv6ToIPv4 ON CLUSTER default;
DROP FUNCTION IF EXISTS ipstr_helper ON CLUSTER default;
DROP FUNCTION IF EXISTS regexp_substr ON CLUSTER default;
DROP FUNCTION IF EXISTS fsaverdict_i2s ON CLUSTER default;
DROP FUNCTION IF EXISTS fsaverdict_s2i ON CLUSTER default;
DROP FUNCTION IF EXISTS logdevtype_from_devid ON CLUSTER default;
DROP FUNCTION IF EXISTS json_extract ON CLUSTER default;
DROP FUNCTION IF EXISTS _json_value3_helper ON CLUSTER default;
DROP FUNCTION IF EXISTS _json_value2_helper ON CLUSTER default;
DROP FUNCTION IF EXISTS json_value ON CLUSTER default;
DROP FUNCTION IF EXISTS cities_distance ON CLUSTER default;
DROP FUNCTION IF EXISTS ep_vuln_sev_dict_s2i ON CLUSTER default;
DROP FUNCTION IF EXISTS formatTimeDuration ON CLUSTER default;
DROP FUNCTION IF EXISTS isPrivateIP ON CLUSTER default;

-- CREATE FUNCTIONS
CREATE FUNCTION IF NOT EXISTS regexp_substr ON CLUSTER default AS (msg,pat) -> extract(msg, pat);
CREATE FUNCTION IF NOT EXISTS generate_series ON CLUSTER default AS (start,end,step) -> arrayJoin(range(start,end+step,step));
CREATE FUNCTION IF NOT EXISTS btrim ON CLUSTER default AS (msg) -> rtrim(ltrim(msg));
CREATE FUNCTION IF NOT EXISTS split_part ON CLUSTER default AS (s, delim, n) -> splitByChar(delim, coalesce(s,''))[n];
CREATE FUNCTION IF NOT EXISTS fct_webcat ON CLUSTER default AS (s) -> coalesce(nullif(split_part(s, ':', 2), ''), s);
CREATE FUNCTION IF NOT EXISTS safe_divide ON CLUSTER default AS (x,y) -> multiIf(y != 0, x/y, 0);
CREATE FUNCTION IF NOT EXISTS safer_divide ON CLUSTER default AS (x,y) -> multiIf(isInfinite(x/y), 0, isNaN(x/y), 0, x/y);
CREATE FUNCTION IF NOT EXISTS format_numeric_no_decimal ON CLUSTER default AS num -> toString(toDecimal64(num, 0));
CREATE FUNCTION IF NOT EXISTS format_numeric ON CLUSTER default AS num -> toString(toDecimal64(num, 2));
CREATE FUNCTION IF NOT EXISTS bandwidth_unit ON CLUSTER default AS (x) -> multiIf(x>= 1024*1024*1024,  CONCAT(format_numeric(x/(1024*1024*1024)),'GB'), x>= 1024*1024, CONCAT(format_numeric(x/(1024*1024)), 'MB'), x>= 1024, CONCAT(format_numeric(x/1024), 'KB'), CONCAT(format_numeric(x), ' '));
CREATE FUNCTION IF NOT EXISTS os2index ON CLUSTER default AS os -> indexOf(['Windows', 'Mac', 'iPad OS', 'iPhone OS', 'iPod OS', 'Android Phone', 'Android Tablet'], os);
CREATE FUNCTION IF NOT EXISTS index2Os ON CLUSTER default AS index -> (['Windows PC', 'Mac OS X', 'iPad OS', 'iPhone OS', 'iPod OS', 'Android Phone', 'Android Tablet'][index]);
CREATE FUNCTION IF NOT EXISTS fctos_to_devtype ON CLUSTER default AS os -> multiIf(os2index(os) > 0, index2Os(os2index(os)), 'Unknown');
CREATE FUNCTION IF NOT EXISTS is_fgt_6k7k ON CLUSTER default AS (dev, i) -> (CASE WHEN i IS NULL THEN 0 ELSE (CASE WHEN LEFT(dev,3)='F6K' OR LEFT(dev, 5)='FG-6K' THEN 6 WHEN LEFT(dev, 2)='F7' OR LEFT(dev, 3)='FG7' OR LEFT(dev, 6)='FGT7KE' THEN 7 ELSE 0 END) END);
CREATE FUNCTION IF NOT EXISTS get_fgt_role ON CLUSTER default AS (dev, i) -> (CASE WHEN is_fgt_6k7k(dev, i) = 6 THEN (CASE WHEN i=0 THEN 'MBD' ELSE 'FPC' END) WHEN is_fgt_6k7k(dev, i) = 7 THEN (CASE WHEN i in (1,2) THEN 'FIM' ELSE 'FPM' END) ELSE NULL END);
CREATE FUNCTION IF NOT EXISTS match_question ON CLUSTER default AS (path) -> multiIf(position(path, '?') > 0, substr(path, 1, position(path, '?')-1), path);
CREATE FUNCTION IF NOT EXISTS match_path ON CLUSTER default AS (path) -> extract(path, '([^;#{}\[\]?/]+)');
CREATE FUNCTION IF NOT EXISTS remove_trailing ON CLUSTER default AS (path, len) -> multiIf(len < 2, path, substr(path,len) = '/', substr(path, 1, len-1), path);
CREATE FUNCTION IF NOT EXISTS remove_host_prefix ON CLUSTER default AS (protocol, hostname, path) -> substr(path, length(protocol) + 4 + length(hostname));
CREATE FUNCTION IF NOT EXISTS is_host_prefix ON CLUSTER default AS (protocol, hostname, path) -> multiIf(position(path, concat(protocol, '://', hostname)) = 1, 1, 0);
CREATE FUNCTION IF NOT EXISTS massage_path ON CLUSTER default AS (protocol, hostname, path) -> multiIf(is_host_prefix(protocol, hostname, path), remove_host_prefix(protocol, hostname, path), path);
CREATE FUNCTION IF NOT EXISTS finalize_path ON CLUSTER default AS (protocol, hostname, path, tdtype) -> multiIf(substr(tdtype, 1, 1) = 'i', remove_trailing(match_question(path),length(match_question(path))), length(path) > 1, match_path(path), path);
CREATE FUNCTION IF NOT EXISTS add_port ON CLUSTER default AS (protocol, port) -> multiIf(protocol = 'http' AND port = 80, '', protocol = 'https' AND port = 443, '', concat(':', toString(port)));
CREATE FUNCTION IF NOT EXISTS normalize_url ON CLUSTER default AS (protocol, hostname, path, port, tdtype) -> concat(lcase(protocol), '://', hostname, add_port(lcase(protocol), port), finalize_path(lcase(protocol), hostname, massage_path(lcase(protocol), hostname, path), tdtype));
CREATE FUNCTION IF NOT EXISTS event_level_i2s ON CLUSTER default AS i -> (['debug', 'information', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency'][i]);
CREATE FUNCTION IF NOT EXISTS event_level_s2i ON CLUSTER default AS l -> indexOf(['debug', 'information', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency'], l);
CREATE FUNCTION IF NOT EXISTS ts_itime ON CLUSTER default AS t -> toDateTime(t);
CREATE FUNCTION IF NOT EXISTS ts_dtime ON CLUSTER default AS t -> toTimeZone(toDateTime(t), 'UTC');
CREATE FUNCTION IF NOT EXISTS from_itime ON CLUSTER default AS t -> formatDateTime(ts_itime(t), '%Y-%m-%d %H:%i:%s'); -- we can have time zone in the output formatDateTime(ts_itime(t), '%Y-%m-%d %H:%i:%s %z')
CREATE FUNCTION IF NOT EXISTS from_dtime ON CLUSTER default AS t -> formatDateTime(ts_dtime(t), '%Y-%m-%d %H:%i:%s'); -- using toString is not safe. Sometimes it doesn't apply the session time zone
CREATE FUNCTION IF NOT EXISTS nanosecond_to_sec ON CLUSTER default AS n -> (n / 1000000000);
CREATE FUNCTION IF NOT EXISTS nanosec_to_sec ON CLUSTER default AS n -> (n / 1000000000);
CREATE FUNCTION IF NOT EXISTS file_name_ext ON CLUSTER default AS f -> multiIf(position(f, '.') > 0, reverse(substr(reverse(f), 1, position(reverse(f), '.') - 1)), NULL);
CREATE FUNCTION IF NOT EXISTS threat_level_i2s ON CLUSTER default AS (i) -> arrayElement(['low','medium','high','critical'], i);
CREATE FUNCTION IF NOT EXISTS threat_level_s2i ON CLUSTER default AS (l) -> indexOf(['low','medium','high','critical'], l);
CREATE FUNCTION IF NOT EXISTS severity_i2s ON CLUSTER default AS (i) -> arrayElement(['Low','Info','Medium','High','Critical'], i);
CREATE FUNCTION IF NOT EXISTS severity_s2i ON CLUSTER default AS (l) -> indexOf(['Low','Info','Medium','High','Critical'], l);
CREATE FUNCTION IF NOT EXISTS get_devtype ON CLUSTER default AS (a,b,c) -> (CASE WHEN a IS NULL THEN c ELSE (CASE WHEN b IS NULL THEN c ELSE CONCAT(b, ' ', a) END) END);
CREATE FUNCTION IF NOT EXISTS nullifna ON CLUSTER default AS (a) -> NULLIF(NULLIF(NULLIF(NULLIF(a, 'N/A'), 'n/a'), '(none)'),'');
CREATE FUNCTION IF NOT EXISTS app_group_name ON CLUSTER default AS (GROUP) -> (CASE WHEN position(GROUP,'_',position(GROUP,'_')+1) > 0 THEN GROUP ELSE (CASE WHEN position(GROUP, '.') > 0 AND position(GROUP, '_') > 0 THEN substr(GROUP, 1, position(GROUP, '_')-1) ELSE GROUP END) END);
CREATE FUNCTION IF NOT EXISTS is_ip ON CLUSTER default AS (HOST) -> match(HOST, '^[0-9:\.\]\[]*$');
CREATE FUNCTION IF NOT EXISTS double_position ON CLUSTER default AS (msg, sym) -> (CASE WHEN position(msg,sym) > 0 THEN  position(msg, sym, position(msg, sym)+1) ELSE 0 END);
CREATE FUNCTION IF NOT EXISTS root_domain ON CLUSTER default AS HOST -> multiIf(is_ip(HOST), HOST, (position(HOST, '.') > 0) AND (double_position(reverse(HOST), '.') > 0), reverse(substring(reverse(HOST), 1, double_position(reverse(HOST), '.') - 1)), HOST);
CREATE FUNCTION IF NOT EXISTS threatweight_level_sum ON CLUSTER default AS (LEVEL, levels, counts, weights) -> arraySum(i -> (CASE WHEN arrayElement(levels,i) = LEVEL THEN arrayElement(weights,i) * arrayElement(counts, i)  ELSE 0 END), range(1, length(levels)+1));
CREATE FUNCTION IF NOT EXISTS threatweight_sum ON CLUSTER default AS (weights, counts) -> arraySum(i -> arrayElement(weights,i) * arrayElement(counts, i), range(1, length(weights)+1));
CREATE FUNCTION IF NOT EXISTS threatlevel_max ON CLUSTER default AS (arr) -> arrayMax(arr);
CREATE FUNCTION IF NOT EXISTS fv_timescale_func ON CLUSTER default AS (timescale, interval, OFFSET) -> toDateTime((toInt64(((toInt64(timescale) + OFFSET) / interval)) * interval) - OFFSET);
CREATE FUNCTION IF NOT EXISTS vpn_trim ON CLUSTER default AS v -> multiIf(match(v, '.*_[0-9]+$'),extract(v, '(.*)_[0-9]+$'),v);
CREATE FUNCTION IF NOT EXISTS devvd_str ON CLUSTER default AS (arr, index) -> concat(arr, '[', index, ']');
CREATE FUNCTION IF NOT EXISTS coalesce_str ON CLUSTER default AS (a, b) -> multiIf(NOT empty(a), a, NOT empty(b), b, NULL);
CREATE FUNCTION IF NOT EXISTS coalesce_str3 ON CLUSTER default AS (a, b, c) -> multiIf(NOT empty(a), a, NOT empty(b), b, NOT empty(c), c, NULL);
CREATE FUNCTION IF NOT EXISTS coalesce_str4 ON CLUSTER default AS (a, b, c, d) -> multiIf(NOT empty(a), a, NOT empty(b), b, NOT empty(c), c, NOT empty(d), d, NULL);
CREATE FUNCTION IF NOT EXISTS logid_to_int ON CLUSTER default AS (a) -> multiIf(length(a) > 6,toUInt64(right(a,6)),empty(a),0,toUInt64(a));
CREATE FUNCTION IF NOT EXISTS convert_unit ON CLUSTER default AS (a) -> ([1024, 1048576, 1073741824, 1099511627776, 1125899906842624, 1, 1024, 1048576, 1073741824, 1099511627776, 1125899906842624][indexOf(['K', 'M', 'G', 'T', 'E', 'BPS', 'KBPS', 'MBPS', 'GBPS', 'TBPS', 'EBPS'], a)]);
CREATE FUNCTION IF NOT EXISTS convert_unit_to_number ON CLUSTER default AS a -> multiIf(empty(a), 0, match(a, '[^\\.0-9]+'), convert_unit(upper(extract(a, '[^\\.0-9 ]+'))) * toFloat64OrZero(extract(a, '[\\.0-9]+')), toFloat64OrZero(extract(a, '[\\.0-9]+')));
CREATE FUNCTION IF NOT EXISTS convert_unit_to_num ON CLUSTER default AS (a) -> multiIf(match(a, '[^\.0-9]+'), convert_unit(upper(extract(a, '[^\.0-9 ]+'))) * toFloat64(extract(a, '[\.0-9]+')), toFloat64(extract(a, '[\.0-9]+')));
CREATE FUNCTION IF NOT EXISTS safeToFloat32 ON CLUSTER default AS (a) -> toFloat32OrZero(string_to_num(a));
CREATE FUNCTION IF NOT EXISTS safeValue ON CLUSTER default AS (a) -> multiIf(isNaN(a), 0, isInfinite(a), 0, a);
CREATE FUNCTION IF NOT EXISTS safeToDecimalStr ON CLUSTER default AS (a) -> toString(safeValue(round(a,2)));
CREATE FUNCTION IF NOT EXISTS string_to_num ON CLUSTER default AS (a) -> multiIf(empty(a), '0', extract(a, '^([0-9\.]+)'));
CREATE FUNCTION IF NOT EXISTS isIPv4 ON CLUSTER default AS ip -> (bitShiftRight(ip,32) = 0xffff);
CREATE FUNCTION IF NOT EXISTS IPv6ToIPv4 ON CLUSTER default AS ip -> toString(toIPv4(toUInt32(bitAnd(ip,0xffffffff))));
CREATE FUNCTION IF NOT EXISTS is_Zero_IPv6 ON CLUSTER default AS ip -> (ip = '::' OR ip = '::ffff:0.0.0.0');
CREATE FUNCTION IF NOT EXISTS ip_subnet ON CLUSTER default AS ip -> multiIf(isIPv4(ip),concat(replaceRegexpOne(cutIPv6(ip,0,1), '^::ffff:', ''), '/24'), concat(cutIPv6(ip,8,0), '/64'));
CREATE FUNCTION IF NOT EXISTS ip_subnet_contains ON CLUSTER default AS (ip, subnet) -> multiIf(isNull(ip),0,isIPAddressInRange(ipstr(coalesce(ip,toIPv6('::'))), subnet));
CREATE FUNCTION IF NOT EXISTS ipstr_helper ON CLUSTER default AS ip -> multiIf(isIPv4(ip), IPv6ToIPv4(ip),toString(ip));
CREATE FUNCTION IF NOT EXISTS iparray_to_string ON CLUSTER default AS (ips, sep) -> arrayStringConcat(arrayMap(ip -> ipstr(ip), ips), sep);
CREATE FUNCTION IF NOT EXISTS ipstr ON CLUSTER default AS ip -> ipstr_helper(toIPv6(ip));
CREATE FUNCTION IF NOT EXISTS host ON CLUSTER default AS ip -> ipstr(ip);
CREATE FUNCTION IF NOT EXISTS string_position ON CLUSTER default AS (needle,haystack) -> position(haystack,needle);
CREATE FUNCTION IF NOT EXISTS extract_epoch ON CLUSTER default AS (ts) -> toInt32(toDateTime(concat('1970-01-01 ',ts)));
CREATE FUNCTION IF NOT EXISTS extract_epoch_from_timestr ON CLUSTER default AS (msg,pre) -> extract_epoch(extract(msg, concat(pre,'([0-9]{2}:[0-9]{2}:[0-9]{2})')));
CREATE FUNCTION IF NOT EXISTS virusid_to_str ON CLUSTER default AS (virus, id) -> multiIf(id = 'botnet', concat(toString(id), ':', toString(virus)), toString(virus));
CREATE FUNCTION IF NOT EXISTS inc_cat_encode ON CLUSTER default AS (cat) -> multiIf(match(cat,'CAT[1-6]'), 'inc_cat_' || cat, cat);
CREATE FUNCTION IF NOT EXISTS strpos ON CLUSTER default AS (haystack, needle) -> position(haystack, needle);
CREATE FUNCTION IF NOT EXISTS incid_to_str ON CLUSTER default AS (incid) -> 'IN' || leftPad(toString(incid), 8, '0');
CREATE FUNCTION IF NOT EXISTS email_domain ON CLUSTER default AS (e) -> arrayElement(splitByChar('@', coalesce(e,'')), 2);
CREATE FUNCTION IF NOT EXISTS email_user ON CLUSTER default AS (e) -> arrayElement(splitByChar('@', coalesce(e,'')), 1);
CREATE FUNCTION IF NOT EXISTS fsaverdict_i2s ON CLUSTER default AS (i) -> arrayElement(['submission failed','pending','unknown','clean','low risk','medium risk','high risk','malicious'], i);
CREATE FUNCTION IF NOT EXISTS fsaverdict_s2i ON CLUSTER default AS (l) -> indexOf(['submission failed','pending','unknown','clean','low risk','medium risk','high risk','malicious'], l);
CREATE FUNCTION IF NOT EXISTS logdevtype_from_devid ON CLUSTER default AS (dev) -> multiIf(match(dev, '^(FV|FWB)'), 5, match(dev, '^(FE|FCT|FCL)'), 3, match(dev, '^(L|A|C|N|F(G|O|P|K|T|D|R|6|7|1|2|3|S|W|C))'), 0, -1);
CREATE FUNCTION IF NOT EXISTS json_extract ON CLUSTER default AS (d, key) -> nullif(JSONExtractString(d, key), '');
CREATE FUNCTION IF NOT EXISTS _json_value3_helper ON CLUSTER default AS (d, key) -> nullif(JSONExtractString(d, key), '');
CREATE FUNCTION IF NOT EXISTS _json_value2_helper ON CLUSTER default AS (j, keys) -> multiIf(length(keys) = 1, _json_value3_helper(j, keys[1]), length(keys) = 2, _json_value3_helper( _json_value3_helper(j, keys[1]), keys[2]), length(keys) = 3, _json_value3_helper( _json_value3_helper(_json_value3_helper(j, keys[1]), keys[2]), keys[3]), length(keys) = 4, _json_value3_helper(_json_value3_helper( _json_value3_helper(_json_value3_helper(j, keys[1]), keys[2]), keys[3]), keys[4]), NULL);
CREATE FUNCTION IF NOT EXISTS json_value ON CLUSTER default AS (j, key) -> _json_value2_helper(j, arraySlice(splitByChar('.', key),2));

CREATE FUNCTION IF NOT EXISTS ep_vuln_sev_dict_s2i ON CLUSTER default AS (l) -> indexOf(['Clean','Low','Medium','High','Critical'], l);
CREATE FUNCTION IF NOT EXISTS formatTimeDuration ON CLUSTER default AS (seconds) -> (
    if(
        seconds = 0,
        '0s',  -- Show 0s when there are no other units
        concat(
            if(floor(seconds/86400) > 0, concat(toString(floor(seconds/86400)), 'd'), ''),
            if(floor((seconds % 86400)/3600) > 0, concat(toString(floor((seconds % 86400)/3600)), 'h'), ''),
            if(floor((seconds % 3600)/60) > 0, concat(toString(floor((seconds % 3600)/60)), 'm'), ''),
            if(seconds % 60 > 0, concat(toString(seconds % 60), 's'), '')
        )
    )
); -- convert input 110101seconds to 1d6h35m1s
CREATE FUNCTION IF NOT EXISTS isPrivateIP ON CLUSTER default AS (ip) -> (
    CASE
        -- Check for IPv4-mapped IPv6 addresses (e.g., ::ffff:192.168.1.1)
        WHEN startsWith(IPv6NumToString(ip), '::ffff:') THEN
            IPv4StringToNum(substring(IPv6NumToString(ip), 8)) BETWEEN IPv4StringToNum('10.0.0.0') AND IPv4StringToNum('10.255.255.255') OR
            IPv4StringToNum(substring(IPv6NumToString(ip), 8)) BETWEEN IPv4StringToNum('172.16.0.0') AND IPv4StringToNum('172.31.255.255') OR
            IPv4StringToNum(substring(IPv6NumToString(ip), 8)) BETWEEN IPv4StringToNum('192.168.0.0') AND IPv4StringToNum('192.168.255.255')
        -- Check for IPv6 private ranges (ULA)
        WHEN IPv6NumToString(ip) LIKE 'fc%' OR IPv6NumToString(ip) LIKE 'fd%' THEN
            1
        ELSE
            0
    END
);

--faz_func_version() must be the last function in this file.
--change SIEMDB_FAB_FV_TEMPL_FUNCTION_VERSION after change this file.
CREATE FUNCTION IF NOT EXISTS faz_func_version ON CLUSTER default AS () -> ('$VERSION');

EOF
)

# ================================
# Execute SQL in the ClickHouse pod
# ================================
echo "Executing SQL on ClickHouse pod: $POD_NAME"
echo "======================"
echo "Executing the following SQL:"
echo "======================"
echo "$SQL"
echo "======================"
kubectl --kubeconfig="$KUBECONFIG" -n "$NAMESPACE" exec -i "$POD_NAME" -- \
    clickhouse-client -u admin --password ${CLICKHOUSE_ADMIN_PASSWORD} --database="$DATABASE_NAME" --multiquery <<< "$SQL"

echo "Functions dropped and created successfully on cluster '$CLUSTER_NAME'."