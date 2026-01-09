description.md
description_list_all_storage_facet_result.md
list_all_storage_facet_result.sh
recreate_facet_result.sh

// Merge the above 2 scripts: 
// if no parameters, list all storage_id and relevant hash partition settings
// if there is parameter of storage_id list ( support multi storage_id separated by comma), execute recreate table one by one. And finally list all storage_id and relevant hash partition settings again.


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
   parameters: none
   parameters: storage_id={one storage_id}
   parameters: storage_id={two storage_id}