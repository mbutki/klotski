#!/bin/bash
sudo SPDY_Proxy/bin/spdyproxy -p 44300 -f fingerprint.json -c server.crt -k server.key --push --reprio
