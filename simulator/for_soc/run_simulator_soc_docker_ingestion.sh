#!/bin/bash
IMAGE_NAME="353941098768.dkr.ecr.us-west-1.amazonaws.com/platform/snapshot/com.fortidata.simulator:soclatest"
if [[ $# -gt 0 ]]
then
  key="$1"
fi
case $key in
  stop)
    echo "just stop"
    docker rm -f ${HOSTNAME}-simulator
    echo "done"
    exit 0
    ;;
  *)    # unknown option
    echo "restart..."
    ;;
esac
echo "Starting Simulator"
#docker pull $IMAGE_NAME
docker rm ${HOSTNAME}-simulator 2>/dev/null || true

docker run \
 --cpus=2 \
 --name ${HOSTNAME}-simulator \
 --network host \
 -v /Users/lei/Documents/wsForti/worktmp/simulator/for_soc/ingestion.conf:/simulator/in.conf \
 ${IMAGE_NAME} java -jar simulator.jar -f /simulator/in.conf

echo "Done"