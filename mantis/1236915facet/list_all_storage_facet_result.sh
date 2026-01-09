#!/bin/bash

# Get all storage_ids from consul
STORAGE_IDS=$(curl -s http://consul.service.consul:8500/v1/kv/config/storage_group_status | jq -r '.[0].Value' | base64 --decode | jq -r '.[].storageId')

# Loop through each storage_id
for STORAGE_ID in $STORAGE_IDS; do
  echo "Storage ID: $STORAGE_ID"
  
  # Get the hash partition settings from impala
  HASH_PARTITION=$(impala-shell -d db_log_public -q "show create table __${STORAGE_ID}_facet_result;" 2>/dev/null | grep "PARTITION BY" || echo "Table did not exist or has no partition settings.")
  
  echo "Hash partition settings: $HASH_PARTITION"
  echo "----------------------------------------"
done
