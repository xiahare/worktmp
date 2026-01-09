# script parameters

storage_id=xxxx
xxxx is a storage_id

# process flow

step 0:
// check if storage_id exists via consul
"storageName":"name (storage_id)"
please refer to the sample in Samples part
if the storage_id does not exists, please return and echo "The storage_id of ${storage_id} does NOT exist" and list all current storage_id
step 1:

// run sql via impala-shell

check if these tables exist,
If exists, please output the current hash partition settings of table __${storage_id}_facet_result via 'show create table xxxx'
drop table __${storage_id}_facet_result;
drop table __${storage_id}_facet_process;
connect impala client: impala-shell -d db_log_public

step 2:
// refresh hash partition configurations in catalog 
curl -X POST http://data-catalog-server.service.consul.:8080/datacatalog/v1/storages/{storage_id}/update_type_config
step 3:
// recreate facet tables by async api
http://data-catalog-server.service.consul.:8080/datacatalog/v1/storages/integrity/check/start
tableSchemaCheck=true : Perform only a table schema check.
// loop check status and result based on taskid
http://data-catalog-server.service.consul.:8080/datacatalog/v1/data/async/fetch


step 4:
// clean redis cache by api
curl -X GET --header 'Accept: application/json' 'http://data-server.service.consul.:8080/data/v0/facets/redis/cleanup?pattern=fazconnector::facetMeta::*'|jq

stip 5:
check if __${storage_id}_facet_result and __${storage_id}_facet_process exists via impala
If exists, please output the current and previous hash partition settings of table __${storage_id}_facet_result via 'show create table xxxx' 


# Test

1. ssh to a server env to execute script
ssh root@10.105.101.4
password: fortinet@123
2. working directory
/data2/xl/
create the directory if not exists
3. execute the script
rsync the script to this directory with the newest version
run the script with exe mode to test if it works
parameters: storage_id=gftauvkx


# Samples

// Key/Values sample value for config/storage_group_status in consul

[{"createdTimestamp":1726872271764,"updatedTimestamp":1746134109941,"status":"ready","code":"","message":"","tenantId":"db_log_public","storageId":"root","storageName":"Root (root)","description":null,"action":"create","properties":{"storageTypeVersion":"4","storageGroupType":"default","customStorageGroupTypeDetails":""},"hotPhase":{"hashPartition":"6","hashPartitionColumns":"id","rangePartitionColumns":"itime","replicas":"3","retentionPeriod":60,"partitionPeriod":3,"unit":"day","diskAllocation":135829962175242,"overridePartition":{"fgt_webfilter":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"3","unit":"day","replicas":"3"},"facet_result":{"hashPartition":"6;6","hashPartitionColumns":"hash_id,adomid;row_no","rangePartitionColumns":"start_time","partitionPeriod":"3","unit":"day","replicas":"3"},"fgt_app_ctrl":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"3","unit":"day","replicas":"3"},"fgt_event":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"3","unit":"day","replicas":"3"},"fgt_hyperscale":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"1","unit":"day","replicas":"3"},"fgt_traffic":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"1","unit":"day","replicas":"3"}},"userOverridePartition":{}},"warmPhase":{"enableWarmPhase":false,"phaseAge":30,"unit":"day","hdfsUrl":null},"coldPhase":{"enableColdPhase":false,"phaseAge":180,"unit":"day"},"poolId":"fead8379-4a55-4f6c-b882-abd79c4ed4c8","storageGroupType":"default","storageTypeVersion":"4","logsRetentionDisplay":"60 days","diskAllocationDisplay":"123 TB","customStorageGroupTypeDetails":""},{"createdTimestamp":1731032171065,"updatedTimestamp":1741397793617,"status":"ready","code":"","message":"","tenantId":"db_log_public","storageId":"okz7pn13","storageName":"nodevid (okz7pn13)","description":null,"action":"create","properties":{"storageTypeVersion":"4","storageGroupType":"default","customStorageGroupTypeDetails":""},"hotPhase":{"hashPartition":"6","hashPartitionColumns":"id","rangePartitionColumns":"itime","replicas":"3","retentionPeriod":60,"partitionPeriod":3,"unit":"day","diskAllocation":26570951300685,"overridePartition":{"fgt_webfilter":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"3","unit":"day","replicas":"3"},"facet_result":{"hashPartition":"6;6","hashPartitionColumns":"hash_id,adomid;row_no","rangePartitionColumns":"start_time","partitionPeriod":"3","unit":"day","replicas":"3"},"fgt_app_ctrl":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"3","unit":"day","replicas":"3"},"fgt_event":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"3","unit":"day","replicas":"3"},"fgt_hyperscale":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"1","unit":"day","replicas":"3"},"fgt_traffic":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"1","unit":"day","replicas":"3"}},"userOverridePartition":{}},"warmPhase":{"enableWarmPhase":false,"phaseAge":30,"unit":"day","hdfsUrl":null},"coldPhase":{"enableColdPhase":false,"phaseAge":180,"unit":"day"},"poolId":"1f6f6577-0b7c-4f9c-aae7-80c194ba32f0","storageGroupType":"default","storageTypeVersion":"4","logsRetentionDisplay":"60 days","diskAllocationDisplay":"24 TB","customStorageGroupTypeDetails":""},{"createdTimestamp":1730330994960,"updatedTimestamp":1741397793626,"status":"ready","code":"","message":"","tenantId":"db_log_public","storageId":"nfykhc04","storageName":"Test2 (nfykhc04)","description":null,"action":"create","properties":{"storageTypeVersion":"4","storageGroupType":"default","customStorageGroupTypeDetails":""},"hotPhase":{"hashPartition":"6","hashPartitionColumns":"id","rangePartitionColumns":"itime","replicas":"3","retentionPeriod":60,"partitionPeriod":3,"unit":"day","diskAllocation":1099511627776,"overridePartition":{"fgt_webfilter":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"3","unit":"day","replicas":"3"},"facet_result":{"hashPartition":"6;6","hashPartitionColumns":"hash_id,adomid;row_no","rangePartitionColumns":"start_time","partitionPeriod":"3","unit":"day","replicas":"3"},"fgt_app_ctrl":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"3","unit":"day","replicas":"3"},"fgt_event":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"3","unit":"day","replicas":"3"},"fgt_hyperscale":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"1","unit":"day","replicas":"3"},"fgt_traffic":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"1","unit":"day","replicas":"3"}},"userOverridePartition":{}},"warmPhase":{"enableWarmPhase":false,"phaseAge":30,"unit":"day","hdfsUrl":null},"coldPhase":{"enableColdPhase":false,"phaseAge":180,"unit":"day"},"poolId":"e0a00d1b-f0e2-406a-b052-579e4c1e6f6f","storageGroupType":"default","storageTypeVersion":"4","logsRetentionDisplay":"60 days","diskAllocationDisplay":"1 TB","customStorageGroupTypeDetails":""},{"createdTimestamp":1728076274014,"updatedTimestamp":1741397793633,"status":"ready","code":"","message":"","tenantId":"db_log_public","storageId":"gftauvkx","storageName":"Test (gftauvkx)","description":null,"action":"create","properties":{"storageTypeVersion":"4","storageGroupType":"default","customStorageGroupTypeDetails":""},"hotPhase":{"hashPartition":"6","hashPartitionColumns":"id","rangePartitionColumns":"itime","replicas":"3","retentionPeriod":60,"partitionPeriod":3,"unit":"day","diskAllocation":12759266893320,"overridePartition":{"fgt_webfilter":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"3","unit":"day","replicas":"3"},"facet_result":{"hashPartition":"6;6","hashPartitionColumns":"hash_id,adomid;row_no","rangePartitionColumns":"start_time","partitionPeriod":"3","unit":"day","replicas":"3"},"fgt_app_ctrl":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"3","unit":"day","replicas":"3"},"fgt_event":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"3","unit":"day","replicas":"3"},"fgt_hyperscale":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"1","unit":"day","replicas":"3"},"fgt_traffic":{"hashPartition":"13","hashPartitionColumns":"id","rangePartitionColumns":"itime","partitionPeriod":"1","unit":"day","replicas":"3"}},"userOverridePartition":{}},"warmPhase":{"enableWarmPhase":false,"phaseAge":30,"unit":"day","hdfsUrl":null},"coldPhase":{"enableColdPhase":false,"phaseAge":180,"unit":"day"},"poolId":"cc7c2901-bc22-4e6b-9c84-462dfb99e344","storageGroupType":"default","storageTypeVersion":"4","logsRetentionDisplay":"60 days","diskAllocationDisplay":"11 TB","customStorageGroupTypeDetails":""}]