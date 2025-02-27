#!/bin/bash
# Bulk export from Kudu to Parquet with optimized dynamic batching based on time range

# ------ Configuration Section ------
# Impala connection
IMPALA_HOST=""
IMPALA_OPTS=""

# Table configuration
SOURCE_TABLE="db_log_public.__root_fgt_traffic"
TARGET_TABLE="db_log_public.dataset_fgt_traffic_parquet"
HDFS_LOCATION="/dataset/parquet/traffic"

# Batch configuration
TIME_RANGE_START="2025-01-03 06:26:19"
TIME_RANGE_END="2025-01-03 12:17:32"
BATCH_INTERVAL=3600  # 1 hour in seconds (can be set to 1800 for 30 minutes, 600 for 10 minutes, etc.)

# Resource configuration
PARQUET_FILE_SIZE="1g"  # Target Parquet file size

current_start="$TIME_RANGE_START"
batch_num=1

# Record start time (epoch format)
script_start_time=$(date +%s)

while [[ "$(date -d "$current_start" +%s)" -lt "$(date -d "$TIME_RANGE_END" +%s)" ]]; do
  
  # Calculate batch end time by adding BATCH_INTERVAL (in seconds) to current_start
  batch_end=$(date -d "@$(($(date -d "$current_start" +%s) + $BATCH_INTERVAL))" +'%F %T')
  
  # Ensure batch_end does not exceed TIME_RANGE_END
  if [[ "$(date -d "$batch_end" +%s)" -gt "$(date -d "$TIME_RANGE_END" +%s)" ]]; then
    batch_end="$TIME_RANGE_END"
  fi

  echo "[$(date +'%F %T')] Processing Batch $batch_num | Current Start: $current_start | Batch End: $batch_end"

  # Step 2: Execute parallel export
  impala-shell $IMPALA_OPTS -q "
    -- Session configuration
    SET MEM_LIMIT=40g;
    SET PARQUET_FILE_SIZE=$PARQUET_FILE_SIZE;
    SET COMPRESSION_CODEC=snappy;
    SET RUNTIME_FILTER_MODE=GLOBAL;

    INSERT INTO $TARGET_TABLE
    (
              \`itime\`, \`adomid\`, \`devid\`, \`vd\`, \`id\`, \`dtime\`, \`euid\`, \`epid\`, 
      \`dsteuid\`, \`dstepid\`, \`logflag\`, \`logver\`, \`sfsid\`, \`logid\`, \`type\`, 
      \`subtype\`, \`level\`, \`action\`, \`utmaction\`, \`policyid\`, \`sessionid\`, 
      \`srcip\`, \`dstip\`, \`tranip\`, \`transip\`, \`srcport\`, \`dstport\`, \`tranport\`, 
      \`transport\`, \`trandisp\`, \`duration\`, \`proto\`, \`vrf\`, \`slot\`, \`sentbyte\`, 
      \`rcvdbyte\`, \`sentdelta\`, \`rcvddelta\`, \`sentpkt\`, \`rcvdpkt\`, \`user\`, 
      \`unauthuser\`, \`dstunauthuser\`, \`srcname\`, \`dstname\`, \`group\`, \`service\`, 
      \`app\`, \`appcat\`, \`fctuid\`, \`srcintfrole\`, \`dstintfrole\`, \`srcserver\`, 
      \`dstserver\`, \`appid\`, \`appact\`, \`apprisk\`, \`wanoptapptype\`, \`policytype\`, 
      \`centralnatid\`, \`channel\`, \`vwpvlanid\`, \`shapingpolicyid\`, \`eventtime\`, 
      \`vwlid\`, \`shaperdropsentbyte\`, \`shaperdroprcvdbyte\`, \`shaperperipdropbyte\`, 
      \`wanin\`, \`wanout\`, \`lanin\`, \`lanout\`, \`crscore\`, \`craction\`, \`crlevel\`, 
      \`countapp\`, \`countav\`, \`countdlp\`, \`countemail\`, \`countips\`, \`countweb\`, 
      \`countwaf\`, \`countssl\`, \`countssh\`, \`countdns\`, \`srcuuid\`, \`dstuuid\`, 
      \`poluuid\`, \`srcmac\`, \`mastersrcmac\`, \`dstmac\`, \`masterdstmac\`, \`srchwvendor\`, 
      \`srchwversion\`, \`srcfamily\`, \`srcswversion\`, \`dsthwvendor\`, \`dsthwversion\`, 
      \`dstfamily\`, \`dstswversion\`, \`devtype\`, \`devcategory\`, \`dstdevtype\`, 
      \`dstdevcategory\`, \`osname\`, \`osversion\`, \`dstosname\`, \`dstosversion\`, 
      \`srccountry\`, \`dstcountry\`, \`srcssid\`, \`dstssid\`, \`srcintf\`, \`dstintf\`, 
      \`srcinetsvc\`, \`dstinetsvc\`, \`unauthusersource\`, \`dstunauthusersource\`, 
      \`authserver\`, \`applist\`, \`vpn\`, \`vpntype\`, \`radioband\`, \`policyname\`, 
      \`policymode\`, \`sslaction\`, \`url\`, \`agent\`, \`comment\`, \`ap\`, \`apsn\`, 
      \`vwlservice\`, \`vwlquality\`, \`collectedemail\`, \`dstcollectedemail\`, 
      \`shapersentname\`, \`shaperrcvdname\`, \`shaperperipname\`, \`msg\`, \`custom_field1\`, 
      \`utmevent\`, \`utmsubtype\`, \`sender\`, \`recipient\`, \`virus\`, \`attack\`, 
      \`hostname\`, \`catdesc\`, \`dlpsensor\`, \`utmref\`, \`tdinfoid\`, \`dstowner\`, 
      \`tdtype\`, \`tdscantime\`, \`tdthreattype\`, \`tdthreatname\`, \`tdwfcate\`, 
      \`threatwgts\`, \`threatcnts\`, \`threatlvls\`, \`saasinfo\`, \`ebtime\`, \`clouduser\`, 
      \`threats\`, \`threattyps\`, \`apps\`, \`countff\`, \`identifier\`, \`securityid\`, 
      \`securityact\`, \`tz\`, \`srcdomain\`, \`counticap\`, \`dstregion\`, \`srcregion\`, 
      \`dstcity\`, \`srccity\`, \`signal\`, \`snr\`, \`dstauthserver\`, \`dstgroup\`, 
      \`dstuser\`, \`tunnelid\`, \`vwlname\`, \`srcthreatfeed\`, \`dstthreatfeed\`, 
      \`psrcport\`, \`pdstport\`, \`srcreputation\`, \`dstreputation\`, \`vip\`, 
      \`accessproxy\`, \`gatewayid\`, \`clientdeviceid\`, \`clientdeviceowner\`, 
      \`clientdevicetags\`, \`httpmethod\`, \`referralurl\`, \`saasname\`, \`srcmacvendor\`, 
      \`shapingpolicyname\`, \`accessctrl\`, \`countcifs\`, \`proxyapptype\`, 
      \`clientdevicemanageable\`, \`emsconnection\`, \`srcremote\`, \`replydstintf\`, 
      \`replysrcintf\`, \`vsn\`, \`countsctpf\`, \`realserverid\`, \`clientdeviceems\`, 
      \`clientcert\`, \`countcasb\`, \`durationdelta\`, \`countvpatch\`, \`sentpktdelta\`, 
      \`rcvdpktdelta\`, \`fwdsrv\`
    )
    SELECT 
          \`itime\`, \`adomid\`, \`devid\`, \`vd\`, \`id\`, \`dtime\`, \`euid\`, \`epid\`, 
      \`dsteuid\`, \`dstepid\`, \`logflag\`, \`logver\`, \`sfsid\`, \`logid\`, \`type\`, 
      \`subtype\`, \`level\`, \`action\`, \`utmaction\`, \`policyid\`, \`sessionid\`, 
      \`srcip\`, \`dstip\`, \`tranip\`, \`transip\`, \`srcport\`, \`dstport\`, \`tranport\`, 
      \`transport\`, \`trandisp\`, \`duration\`, \`proto\`, \`vrf\`, \`slot\`, \`sentbyte\`, 
      \`rcvdbyte\`, \`sentdelta\`, \`rcvddelta\`, \`sentpkt\`, \`rcvdpkt\`, \`user\`, 
      \`unauthuser\`, \`dstunauthuser\`, \`srcname\`, \`dstname\`, \`group\`, \`service\`, 
      \`app\`, \`appcat\`, \`fctuid\`, \`srcintfrole\`, \`dstintfrole\`, \`srcserver\`, 
      \`dstserver\`, \`appid\`, \`appact\`, \`apprisk\`, \`wanoptapptype\`, \`policytype\`, 
      \`centralnatid\`, \`channel\`, \`vwpvlanid\`, \`shapingpolicyid\`, \`eventtime\`, 
      \`vwlid\`, \`shaperdropsentbyte\`, \`shaperdroprcvdbyte\`, \`shaperperipdropbyte\`, 
      \`wanin\`, \`wanout\`, \`lanin\`, \`lanout\`, \`crscore\`, \`craction\`, \`crlevel\`, 
      \`countapp\`, \`countav\`, \`countdlp\`, \`countemail\`, \`countips\`, \`countweb\`, 
      \`countwaf\`, \`countssl\`, \`countssh\`, \`countdns\`, \`srcuuid\`, \`dstuuid\`, 
      \`poluuid\`, \`srcmac\`, \`mastersrcmac\`, \`dstmac\`, \`masterdstmac\`, \`srchwvendor\`, 
      \`srchwversion\`, \`srcfamily\`, \`srcswversion\`, \`dsthwvendor\`, \`dsthwversion\`, 
      \`dstfamily\`, \`dstswversion\`, \`devtype\`, \`devcategory\`, \`dstdevtype\`, 
      \`dstdevcategory\`, \`osname\`, \`osversion\`, \`dstosname\`, \`dstosversion\`, 
      \`srccountry\`, \`dstcountry\`, \`srcssid\`, \`dstssid\`, \`srcintf\`, \`dstintf\`, 
      \`srcinetsvc\`, \`dstinetsvc\`, \`unauthusersource\`, \`dstunauthusersource\`, 
      \`authserver\`, \`applist\`, \`vpn\`, \`vpntype\`, \`radioband\`, \`policyname\`, 
      \`policymode\`, \`sslaction\`, \`url\`, \`agent\`, \`comment\`, \`ap\`, \`apsn\`, 
      \`vwlservice\`, \`vwlquality\`, \`collectedemail\`, \`dstcollectedemail\`, 
      \`shapersentname\`, \`shaperrcvdname\`, \`shaperperipname\`, \`msg\`, \`custom_field1\`, 
      \`utmevent\`, \`utmsubtype\`, \`sender\`, \`recipient\`, \`virus\`, \`attack\`, 
      \`hostname\`, \`catdesc\`, \`dlpsensor\`, \`utmref\`, \`tdinfoid\`, \`dstowner\`, 
      \`tdtype\`, \`tdscantime\`, \`tdthreattype\`, \`tdthreatname\`, \`tdwfcate\`, 
      \`threatwgts\`, \`threatcnts\`, \`threatlvls\`, \`saasinfo\`, \`ebtime\`, \`clouduser\`, 
      \`threats\`, \`threattyps\`, \`apps\`, \`countff\`, \`identifier\`, \`securityid\`, 
      \`securityact\`, \`tz\`, \`srcdomain\`, \`counticap\`, \`dstregion\`, \`srcregion\`, 
      \`dstcity\`, \`srccity\`, \`signal\`, \`snr\`, \`dstauthserver\`, \`dstgroup\`, 
      \`dstuser\`, \`tunnelid\`, \`vwlname\`, \`srcthreatfeed\`, \`dstthreatfeed\`, 
      \`psrcport\`, \`pdstport\`, \`srcreputation\`, \`dstreputation\`, \`vip\`, 
      \`accessproxy\`, \`gatewayid\`, \`clientdeviceid\`, \`clientdeviceowner\`, 
      \`clientdevicetags\`, \`httpmethod\`, \`referralurl\`, \`saasname\`, \`srcmacvendor\`, 
      \`shapingpolicyname\`, \`accessctrl\`, \`countcifs\`, \`proxyapptype\`, 
      \`clientdevicemanageable\`, \`emsconnection\`, \`srcremote\`, \`replydstintf\`, 
      \`replysrcintf\`, \`vsn\`, \`countsctpf\`, \`realserverid\`, \`clientdeviceems\`, 
      \`clientcert\`, \`countcasb\`, \`durationdelta\`, \`countvpatch\`, \`sentpktdelta\`, 
      \`rcvdpktdelta\`, \`fwdsrv\`
    FROM $SOURCE_TABLE
    WHERE itime >= '$current_start' 
      AND itime < '$batch_end';
  "

  # Update counters
  current_start="$batch_end"
  ((batch_num++))
done

# Record end time
script_end_time=$(date +%s)

# Calculate total execution time
execution_time=$((script_end_time - script_start_time))

echo "[$(date +'%F %T')] Export completed. Total execution time: ${execution_time} s. Processed $((batch_num-1)) batches."
