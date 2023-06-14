#!/bin/sh

clear;python3 -c "from security.relay import NodeServer; n = NodeServer($1); n.start()"