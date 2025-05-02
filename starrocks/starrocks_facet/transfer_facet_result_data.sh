#!/bin/bash


# ------ Configuration Section ------
# connection
HOST=""
OPTS=""
DATABASE="db_log_public"

# Table configuration
SOURCE_TABLE="db_log_public.__root_facet_result"
TARGET_TABLE="db_log_public.__root_facet_result_rmrowno"

# Batch configuration
TIME_RANGE_START="2025-02-13 00:00:00"
TIME_RANGE_END="2025-03-01 00:00:00"
BATCH_INTERVAL=28800  # 8 h

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
  mysql -P 9030 -h kube-starrocks-fe-search.service.consul -u root -proot -vvv  $DATABASE $OPTS -e "
    INSERT INTO $TARGET_TABLE
    SELECT * FROM $SOURCE_TABLE
    where start_time>='$current_start' 
      and start_time<'$batch_end';
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
