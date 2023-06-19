#!/bin/bash

export PUBLIC_RELAY_LIST=http://10.1.2.200:8080
cd security

python3 <<EOF

from hidden_service import HiddenService

hs = HiddenService()
hs.start()

EOF

