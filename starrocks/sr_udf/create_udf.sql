CREATE GLOBAL FUNCTION app_group_name(STRING)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.AppGroupName",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION bigint_array_sum(STRING)
RETURNS BIGINT
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.BigintArraySum",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION convert_unit_to_num(STRING)
RETURNS BIGINT
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.ConvertUnitToNum",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION email_domain(STRING)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.EmailDomain",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION format_1hour_span(STRING)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.Format1HourSpan",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION from_itime(BIGINT)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.FromITime",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION fv_timescale_func(BIGINT, INT, INT)
RETURNS BIGINT
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.FvTimescaleFunc",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION get_devtype(STRING, STRING, STRING)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.GetDevType",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION host(STRING)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.Host",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION ioc_tdpattern(STRING, INT, INT, STRING, STRING, STRING, STRING)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.IocTdPattern",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION logid_to_int(STRING)
RETURNS INT
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.LogidToInt",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION normalize_url(STRING, STRING, STRING, INT, STRING)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.NormalizeUrl",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION nullifna(STRING)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.NullIfNa",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION root_domain(STRING)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.RootDomain",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION string_position(STRING, STRING)
RETURNS INT
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.StringPosition",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION threatlevel_max(STRING)
RETURNS INT
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.ThreatLevelMax",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION threatweight_level_sum(INT, STRING, STRING, STRING)
RETURNS DOUBLE
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.ThreatweightLevelSum",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION threatweight_sum(STRING, STRING)
RETURNS INT
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.ThreatWeightSum",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION my_udf_json_get(STRING, STRING)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.UDFJsonGet",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION vpn_trim(STRING)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.VpnTrim",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION devvd_str(STRING, STRING)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.DevvdStr",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION ebtr_value(STRING, INT, INT)
RETURNS INT
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.EbtrValue",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION array_elem_at_unescape(STRING, INT)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.ArrayElemAtUnescape",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);


CREATE GLOBAL FUNCTION get_fgt_role(STRING, INT)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.GetFgtRoleInteger",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION get_fgt_role(STRING, SMALLINT)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.GetFgtRoleShort",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION ipstr(STRING)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.IPStr",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION is_fgt_6k7k(STRING, INT)
RETURNS INT
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.IsFgt6k7kInteger",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION is_fgt_6k7k(STRING, SMALLINT)
RETURNS INT
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.IsFgt6k7kShort",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL FUNCTION from_dtime(BIGINT)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.FromDTime",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL AGGREGATE FUNCTION ebtr_agg_flat(STRING)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.EbtrAggFlatDummy",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);

CREATE GLOBAL AGGREGATE FUNCTION first_agg(STRING)
RETURNS STRING
PROPERTIES (
    "symbol" = "com.fortidata.starrocks.udfs.udf.functions.FirstAgg",
    "type" = "StarrocksJar",
    "file" = "http://starrocks-udfs-service.db.svc.cluster.local:9091/starrocksUdfs.jar"
);