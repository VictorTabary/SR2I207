#!/bin/sh

clear;python3 -c "from security.connection import NodeServer; n = NodeServer($1); n.start()"