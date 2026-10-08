#!/bin/sh
docker exec server tc qdisc replace dev eth0 root netem delay $1ms
