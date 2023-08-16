#!/bin/bash
set +e
docker stop redis
set -e
docker run --net=host --name redis --rm -d redis
