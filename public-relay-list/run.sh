#!/bin/bash

python3 -m uvicorn server:app --reload --host 0.0.0.0 --port 8080