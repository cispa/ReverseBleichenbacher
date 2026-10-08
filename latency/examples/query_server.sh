#!/bin/bash
attacker_ip=$(docker inspect --format '{{ range .NetworkSettings.Networks }}{{ .IPAddress }}{{ end }}' attacker) # Meh, but it works ...
timeout=90
target=server
curl --cacert ../cert/server.crt --resolve ${target}:443:${attacker_ip} https://${target}:443 -m ${timeout} --connect-timeout ${timeout}
