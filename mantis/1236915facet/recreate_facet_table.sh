#!/bin/bash

# Function to list all storage facet results
list_all() {
  echo "Listing all storage facet results..."
  STORAGE_IDS=$(curl -s http://consul.service.consul:8500/v1/kv/config/storage_group_status | jq -r '.[0].Value' | base64 --decode | jq -r '.[].storageId')

  for STORAGE_ID in $STORAGE_IDS; do
    echo "Storage ID: $STORAGE_ID"
    HASH_PARTITION=$(impala-shell -d db_log_public -q "show create table __${STORAGE_ID}_facet_result;" 2>/dev/null | grep "PARTITION BY" || echo "Table did not exist or has no partition settings.")
    echo "Hash partition settings: $HASH_PARTITION"
    echo "----------------------------------------"
  done
}

# Function to recreate facet tables for a given storage_id
recreate() {
  STORAGE_ID=$1
  echo "Recreating facet tables for storage_id: $STORAGE_ID"

  # Step 0: Check if storage_id exists via consul
  echo "Step 0: Checking if storage_id exists in Consul..."
  CONSUL_URL="http://consul.service.consul:8500/v1/kv/config/storage_group_status"
  CONSUL_VALUE=$(curl -s "$CONSUL_URL" | jq -r '.[0].Value' | base64 --decode)

  if ! echo "$CONSUL_VALUE" | jq -e --arg STORAGE_ID "$STORAGE_ID" '.[] | select(.storageId == $STORAGE_ID)' > /dev/null; then
      echo "The storage_id of ${STORAGE_ID} does NOT exist"
      return 1
  fi
  echo "storage_id found in Consul."

  # Step 1: Drop tables using impala-shell
  echo "Step 1: Dropping facet tables..."
  echo "Previous hash partition settings:"
  PREVIOUS_HASH_PARTITION=$(impala-shell -d db_log_public -q "show create table __${STORAGE_ID}_facet_result;" 2>/dev/null | grep "PARTITION BY" || echo "Table did not exist or has no partition settings.")
  echo "$PREVIOUS_HASH_PARTITION"
  impala-shell -d db_log_public -q "drop table if exists __${STORAGE_ID}_facet_result; drop table if exists __${STORAGE_ID}_facet_process;"
  if [ $? -ne 0 ]; then
    echo "Warning: Failed to drop tables in Impala (they might not have existed)."
  else
    echo "Tables dropped."
  fi

  # Step 2: Refresh hash partition configurations
  echo "Step 2: Refreshing hash partition configurations..."
  curl -X POST "http://data-catalog-server.service.consul.:8080/datacatalog/v1/storages/${STORAGE_ID}/update_type_config"
  echo "Hash partition configurations refreshed."

  # Step 3: Recreate facet tables via async API
  echo "Step 3: Recreating facet tables..."
  START_URL="http://data-catalog-server.service.consul.:8080/datacatalog/v1/storages/integrity/check/start?autoCorrectionValue=true&tableSchemaCheck=true"
  TASK_ID_RESPONSE=$(curl -s -X POST "$START_URL")
  TASK_ID=$(echo "$TASK_ID_RESPONSE" | jq -r '.taskId')

  if [ -z "$TASK_ID" ] || [ "$TASK_ID" == "null" ]; then
    echo "Error: Failed to get task ID from the API."
    echo "Response: $TASK_ID_RESPONSE"
    return 1
  fi

  echo "Integrity check started with taskId: $TASK_ID"

  # Loop to check the status
  FETCH_URL="http://data-catalog-server.service.consul.:8080/datacatalog/v1/data/async/fetch?taskId=${TASK_ID}"
  STATUS="running"
  while [[ "$STATUS" == "running" || "$STATUS" == "pending" ]]; do
    echo "Checking task status..."
    STATUS_RESPONSE=$(curl -s "$FETCH_URL")
    STATUS=$(echo "$STATUS_RESPONSE" | jq -r '.taskStatus')
    echo "Current status: $STATUS"
    if [[ "$STATUS" == "running" || "$STATUS" == "pending" ]]; then
      sleep 5
    fi
  done

  RESULT=$(echo "$STATUS_RESPONSE" | jq -r '.taskResult')
  echo "Task finished with status: $STATUS"
  echo "Result: $RESULT"

  if [ "$STATUS" != "success" ]; then
      echo "Error: Task did not complete successfully."
      return 1
  fi

  # Step 4: Clean Redis cache
  echo "Step 4: Cleaning Redis cache..."
  CLEANUP_URL="http://data-server.service.consul.:8080/data/v0/facets/redis/cleanup?pattern=fazconnector::facetMeta::*"
  curl -s -X GET --header 'Accept: application/json' "$CLEANUP_URL" | jq
  echo "Redis cache cleanup command sent."

  # Step 5: Check if tables exist via impala
  echo "Step 5: Verifying table creation..."
  if ! impala-shell -d db_log_public -q "show tables like '__${STORAGE_ID}_facet_result';" | grep -q "__${STORAGE_ID}_facet_result"; then
      echo "Verification failed: __${STORAGE_ID}_facet_result does not exist."
      return 1
  fi

  if ! impala-shell -d db_log_public -q "show tables like '__${STORAGE_ID}_facet_process';" | grep -q "__${STORAGE_ID}_facet_process"; then
      echo "Verification failed: __${STORAGE_ID}_facet_process does not exist."
      return 1
  fi
  echo "Tables __${STORAGE_ID}_facet_result and __${STORAGE_ID}_facet_process successfully recreated."
  echo "Previous hash partition settings:"
  echo "$PREVIOUS_HASH_PARTITION"
  echo "Current hash partition settings:"
  CURRENT_HASH_PARTITION=$(impala-shell -d db_log_public -q "show create table __${STORAGE_ID}_facet_result;" 2>/dev/null | grep "PARTITION BY")
  echo "$CURRENT_HASH_PARTITION"

  echo "Script finished for storage_id: $STORAGE_ID"
  echo "----------------------------------------"
}

# Main logic
if [ -z "$1" ]; then
  list_all
else
  STORAGE_ID_LIST=$(echo $1 | tr "," " ")
  for STORAGE_ID in $STORAGE_ID_LIST; do
    recreate $STORAGE_ID
  done
  list_all
fi
