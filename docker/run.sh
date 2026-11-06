#! /bin/bash

docker rm -f antivirus
docker run --privileged -d --network host --name antivirus -v ./db:/var/lib/clamav --expose 3310 --restart always antivirus:latest
docker logs -f antivirus
