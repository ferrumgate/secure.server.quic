#!/bin/bash
# docker build script

set -e

#read -p 'enter version:' version
version=$(cat Cargo.toml | grep version | head -n 1 | cut -d '=' -f2 | tr -d '"' | tr -d '[:space:]')

# if not set

IMAGE_NAME=secure.server.quic

echo $IMAGE_NAME is building
#docker build --no-cache --progress=plain -f ./dockerfile -t $IMAGE_NAME .
docker build --progress=plain -f ./dockerfile -t $IMAGE_NAME .

echo "$IMAGE_NAME:$version builded"
docker tag $IMAGE_NAME registry.ferrumgate.zero/ferrumgate/$IMAGE_NAME:$version
docker tag $IMAGE_NAME registry.ferrumgate.zero/ferrumgate/$IMAGE_NAME:latest
docker tag $IMAGE_NAME ferrumgate/$IMAGE_NAME:$version

while true; do
    read -p "do you want to push to local registry y/n " yn
    case $yn in
    [Yy]*)
        docker push registry.ferrumgate.zero/ferrumgate/$IMAGE_NAME:$version
        docker push registry.ferrumgate.zero/ferrumgate/$IMAGE_NAME:latest
        break
        ;;
    [Nn]*) exit ;;
    *) echo "please answer yes or no." ;;
    esac
done
