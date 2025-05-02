#!/bin/bash


HOST="kube-starrocks-fe-search.service.consul"
PORT=9030
USER="root"
PASSWORD="root"
DATABASE="db_log_public"

queries=$(tr -d '\n' < queries.sql)

IFS=';' read -r -a queries <<< "$queries"

i=1
for sql in "${queries[@]}"; do
    
    if [[ -n "$sql" ]]; then 
        echo "Executing SQL #$i:"
        # echo "$sql"
        (time mysql -P $PORT -h $HOST -u $USER -p$PASSWORD --silent --raw $DATABASE -e "$sql") 2>&1 | grep real
        echo "-------------------------------"
        ((i++))
    fi
done