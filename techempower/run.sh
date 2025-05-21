#!/usr/bin/env bash

docker build -f ./sib.dockerfile -t sib-server .
docker run --rm -it -p 8080:8080 sib-server