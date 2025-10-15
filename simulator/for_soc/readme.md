# ================== Default ===============
# 1. Change the filepath of "ingestion.conf" in the script of "run_simulator_soc_docker_ingestion.sh"
-v /data2/simulator/ingestion.conf:/simulator/in.conf \
# 2. Modify server connection in config file of ingestion.conf
simulator.avro.server.host=localhost
simulator.avro.server.port=50051

# 3. send
sh run_simulator_soc_docker_ingestion.sh start

# ===========================================
# ================== Optional ===============

# test server - default port: 19999
sh run_simulator_docker_server.sh start

# test config
vi test.conf
## Modify server connection in config file
simulator.avro.server.host=localhost
simulator.avro.server.port=19999

# Start Client
sh run_simulator_docker.sh start

# Advanced: 
## Change config file "test.conf" in the script of "run_simulator_docker.sh"
 -v /data2/simulator/test.conf:/simulator/in.conf \



