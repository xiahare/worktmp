#!/bin/bash

# StarRocks Configuration
STARROCK_HOST="kube-starrocks-fe-search.service.consul"
STARROCK_PORT=9030
STARROCK_USER="root"
STARROCK_PASSWORD="root"
STARROCK_DB="hits"

# Maximum concurrent threads
MAX_THREADS=5

# Estimated batch size (rows per batch)
TARGET_BATCH_SIZE=10000000

# Hardcoded event date counts (from provided query results)
declare -A EVENT_DATA_COUNTS=(
    ["2013-07-31"]=54158160
    ["2013-07-22"]=18605040
    ["2013-07-08"]=15836760
    ["2013-07-10"]=98199210
    ["2013-07-20"]=3437520
    ["2013-07-03"]=177748890
    ["2013-07-28"]=93121410
    ["2013-07-05"]=69979770
    ["2013-07-02"]=65091210
    ["2013-07-30"]=427920
    ["2013-07-06"]=93621990
    ["2013-07-09"]=150008130
    ["2013-07-21"]=233093520
    ["2013-07-23"]=17653230
    ["2013-07-07"]=14644620
    ["2013-07-15"]=251386980
    ["2013-07-29"]=82985640
)

# Start total timer
start_time=$(date +%s)

# Counter for concurrent processes
process_count=0
SEQ_NO=1
# Process all EventDate data
for date in "${!EVENT_DATA_COUNTS[@]}"; do
    row_count=${EVENT_DATA_COUNTS[$date]}
    
    # Calculate number of batches required for this date
    num_batches=$((row_count / TARGET_BATCH_SIZE))
    [[ $((row_count % TARGET_BATCH_SIZE)) -ne 0 ]] && ((num_batches++))

    # Determine the modulo value for UserID partition
    modulo=$num_batches
    [[ $modulo -lt 1 ]] && modulo=1

    echo "Processing EventDate: $date, Rows: $row_count, Batches: $num_batches (MOD(UserID, $modulo))"

    for ((i=0; i<modulo; i++)); do
        # Generate the SQL query for this batch
        sql_query="INSERT INTO iceberg.hits.hits
              SELECT * FROM default_catalog.hits.hits
              WHERE MOD(UserID, $modulo) = $i AND EventDate = '$date';"
        
        # Start processing the batch in the background
        (
        worker=N${SEQ_NO}
        echo "$(date "+%Y-%m-%d %H:%M:%S") $worker : Processing batch for EventDate '$date' with MOD(UserID, $modulo) = $i"
        
        # Start the timer for the batch
        SUB_START_TIME=$(date +%s)
        
        # Execute SQL query
        mysql -vvv -h "${STARROCK_HOST}" -P "${STARROCK_PORT}" -u"${STARROCK_USER}" -p"${STARROCK_PASSWORD}" -D $STARROCK_DB -e "$sql_query"
        
        
        # Check if the batch executed successfully
        if [ $? -eq 0 ]; then
            SUB_END_TIME=$(date +%s)
            SUB_ELAPSED_TIME=$((SUB_END_TIME - SUB_START_TIME))
            echo "$(date "+%Y-%m-%d %H:%M:%S") [$worker] Batch completed in $SUB_ELAPSED_TIME seconds!"
        else
            echo "Failed to execute batch for MOD(UserID, $modulo) = $i and EventDate='$date'."
        fi
        ) &  # End background process
        
        # Store the PID of the background process
        process_count=$((process_count + 1))
        SEQ_NO=$((SEQ_NO + 1))
        
        # Limit the number of concurrent threads to MAX_THREADS
        if [ "$process_count" -ge "$MAX_THREADS" ]; then
            wait -n
            process_count=$((process_count - 1))
        fi

        
    done
done

# Wait for all background processes to finish
wait

# End total timer
end_time=$(date +%s)
total_duration=$((end_time - start_time))

echo "All batches completed in $total_duration seconds!"