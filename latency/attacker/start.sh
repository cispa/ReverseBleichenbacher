#!/bin/bash

if [ ! -d "/attacker/tlslite-ng-bleichenbacher" ]; then
    cd /attacker
    sh ./setup.sh
fi

uv pip install -e /attacker/tlslite-ng-bleichenbacher --no-deps --no-build-isolation
# Use exec sleep infinity for better signal handling
# This allows the container to shut down gracefully when receiving SIGTERM
sleep infinity
