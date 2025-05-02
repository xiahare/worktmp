INSERT INTO __root_facet_result_rmrowno
SELECT * FROM __root_facet_result
where start_time>='2025-02-23 00:00:00' and start_time<'2025-02-24 00:00:00';


nohup ./transfer_facet_result_data.sh > nohupoutput.log 2>&1 &
tail -fn 2000 nohupoutput.log 
