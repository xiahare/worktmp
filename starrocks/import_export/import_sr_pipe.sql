
DROP PIPE IF EXISTS load_large_fgt_traffic;
CREATE PIPE load_large_fgt_traffic
PROPERTIES
(
    "AUTO_INGEST" = "TRUE"
)
AS
INSERT INTO db_log_public.large_fgt_traffic
    (
      itime, adomid, devid, vd, id, dtime, euid, epid, dsteuid, dstepid,
      logflag, logver, sfsid, logid, type, subtype, `level`, action, utmaction,
      policyid, sessionid, srcip, dstip, tranip, transip, srcport, dstport,
      tranport, transport, trandisp, duration, proto, vrf, slot, sentbyte,
      rcvdbyte, sentdelta, rcvddelta, sentpkt, rcvdpkt, `user`, unauthuser,
      dstunauthuser, srcname, dstname, `group`, service, app, appcat, fctuid,
      srcintfrole, dstintfrole, srcserver, dstserver, appid, appact, apprisk,
      wanoptapptype, policytype, centralnatid, channel, vwpvlanid, shapingpolicyid,
      eventtime, vwlid, shaperdropsentbyte, shaperdroprcvdbyte, shaperperipdropbyte,
      wanin, wanout, lanin, lanout, crscore, craction, crlevel, countapp, countav,
      countdlp, countemail, countips, countweb, countwaf, countssl, countssh,
      countdns, srcuuid, dstuuid, poluuid, srcmac, mastersrcmac, dstmac,
      masterdstmac, srchwvendor, srchwversion, srcfamily, srcswversion,
      dsthwvendor, dsthwversion, dstfamily, dstswversion, devtype, devcategory,
      dstdevtype, dstdevcategory, osname, osversion, dstosname, dstosversion,
      srccountry, dstcountry, srcssid, dstssid, srcintf, dstintf, srcinetsvc,
      dstinetsvc, unauthusersource, dstunauthusersource, authserver, applist,
      vpn, vpntype, radioband, policyname, policymode, sslaction, url, agent,
      `comment`, ap, apsn, vwlservice, vwlquality, collectedemail, dstcollectedemail,
      shapersentname, shaperrcvdname, shaperperipname, msg, custom_field1,
      utmevent, utmsubtype, sender, recipient, virus, attack, hostname, catdesc,
      dlpsensor, utmref, tdinfoid, dstowner, tdtype, tdscantime, tdthreattype,
      tdthreatname, tdwfcate, threatwgts, threatcnts, threatlvls, saasinfo, ebtime,
      clouduser, threats, threattyps, apps, countff, identifier, securityid,
      securityact, tz, srcdomain, counticap, dstregion, srcregion, dstcity,
      srccity, `signal`, snr, dstauthserver, dstgroup, dstuser, tunnelid, vwlname,
      srcthreatfeed, dstthreatfeed, psrcport, pdstport, srcreputation, dstreputation,
      vip, accessproxy, gatewayid, clientdeviceid, clientdeviceowner, clientdevicetags,
      httpmethod, referralurl, saasname, srcmacvendor, shapingpolicyname, accessctrl,
      countcifs, proxyapptype, clientdevicemanageable, emsconnection, srcremote,
      replydstintf, replysrcintf, vsn, countsctpf, realserverid, clientdeviceems,
      clientcert, countcasb, durationdelta, countvpatch, sentpktdelta, rcvdpktdelta,
      fwdsrv
    )

SELECT 
      itime, adomid, devid, vd, id, dtime, euid, epid, dsteuid, dstepid,
      logflag, logver, sfsid, logid, type, subtype, `level`, action, utmaction,
      policyid, sessionid, srcip, dstip, tranip, transip, srcport, dstport,
      tranport, transport, trandisp, duration, proto, vrf, slot, sentbyte,
      rcvdbyte, sentdelta, rcvddelta, sentpkt, rcvdpkt, `user`, unauthuser,
      dstunauthuser, srcname, dstname, `group`, service, app, appcat, fctuid,
      srcintfrole, dstintfrole, srcserver, dstserver, appid, appact, apprisk,
      wanoptapptype, policytype, centralnatid, channel, vwpvlanid, shapingpolicyid,
      eventtime, vwlid, shaperdropsentbyte, shaperdroprcvdbyte, shaperperipdropbyte,
      wanin, wanout, lanin, lanout, crscore, craction, crlevel, countapp, countav,
      countdlp, countemail, countips, countweb, countwaf, countssl, countssh,
      countdns, srcuuid, dstuuid, poluuid, srcmac, mastersrcmac, dstmac,
      masterdstmac, srchwvendor, srchwversion, srcfamily, srcswversion,
      dsthwvendor, dsthwversion, dstfamily, dstswversion, devtype, devcategory,
      dstdevtype, dstdevcategory, osname, osversion, dstosname, dstosversion,
      srccountry, dstcountry, srcssid, dstssid, srcintf, dstintf, srcinetsvc,
      dstinetsvc, unauthusersource, dstunauthusersource, authserver, applist,
      vpn, vpntype, radioband, policyname, policymode, sslaction, url, agent,
      `comment`, ap, apsn, vwlservice, vwlquality, collectedemail, dstcollectedemail,
      shapersentname, shaperrcvdname, shaperperipname, msg, custom_field1,
      utmevent, utmsubtype, sender, recipient, virus, attack, hostname, catdesc,
      dlpsensor, utmref, tdinfoid, dstowner, tdtype, tdscantime, tdthreattype,
      tdthreatname, tdwfcate, threatwgts, threatcnts, threatlvls, saasinfo, ebtime,
      clouduser, threats, threattyps, apps, countff, identifier, securityid,
      securityact, tz, srcdomain, counticap, dstregion, srcregion, dstcity,
      srccity, `signal`, snr, dstauthserver, dstgroup, dstuser, tunnelid, vwlname,
      srcthreatfeed, dstthreatfeed, psrcport, pdstport, srcreputation, dstreputation,
      vip, accessproxy, gatewayid, clientdeviceid, clientdeviceowner, clientdevicetags,
      httpmethod, referralurl, saasname, srcmacvendor, shapingpolicyname, accessctrl,
      countcifs, proxyapptype, clientdevicemanageable, emsconnection, srcremote,
      replydstintf, replysrcintf, vsn, countsctpf, realserverid, clientdeviceems,
      clientcert, countcasb, durationdelta, countvpatch, sentpktdelta, rcvdpktdelta,
      fwdsrv
FROM FILES
(
    "path" = "hdfs://198.18.1.10/dataset/parquet/traffic/*",
    "format" = "parquet",
    "hadoop.security.authentication" = "simple",
    "username" = "root",
    "password" = "fortinet@123"
); 

-- Check the task status

-- show pipes;

-- SELECT * FROM information_schema.pipe_files  where LOAD_STATE!='UNLOADED' ORDER BY LOAD_STATE;

-- SELECT count(*) from db_log_public.large_fgt_traffic;