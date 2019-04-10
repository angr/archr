#!/bin/bash -e

if [ -n "$INHIBIT_BUILD" ]; then
	exit
fi

for DOCKERFILE in */Dockerfile
do
	DOCKERDIR=${DOCKERFILE///*}
	DOCKERTAG=archr-test:$DOCKERDIR
	echo "Building $DOCKERDIR"
	docker build -t $DOCKERTAG $DOCKERDIR
done
docker pull ikanak/miniupnpd
