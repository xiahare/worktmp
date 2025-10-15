#!/bin/bash
IMAGE_NAME="353941098768.dkr.ecr.us-west-1.amazonaws.com/platform/snapshot/com.fortidata.simulator:latest"
if [[ $# -gt 0 ]]
then
  key="$1"
fi
case $key in
  stop)
    echo "just stop"
    docker rm -f ${HOSTNAME}-simulator-server
    echo "done"
    exit 0
    ;;
  *)    # unknown option
    echo "restart..."
    ;;
esac

#docker pull $IMAGE_NAME
echo "Stopping Simulator-server"
docker rm ${HOSTNAME}-simulator-server
echo "Starting Simulator-server"
docker run \
 --cpus=2 \
 --name ${HOSTNAME}-simulator-server \
 --network host \
 ${IMAGE_NAME} java -jar simulator.jar -fbs

echo "Done"