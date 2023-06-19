#!/bin/bash

export PUBLIC_RELAY_LIST=http://10.1.2.200:8080
cd security

python3 <<EOF

from client import HiddenServiceClient

h = HiddenServiceClient("abcdefghijklmnopqrstuvwxyz")
h.connect()
h.send("INTRO_CLIENT_SIDE", "heeyyyy")
h.close()

EOF

