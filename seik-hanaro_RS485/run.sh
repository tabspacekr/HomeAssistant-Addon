#!/bin/sh

PY_DIR=/seik
PY_FILE="seik.py"
DEV_FILE="seik_devinfo.json"

# start server
echo "[Info] Start SEIK Controller.."

python -u $PY_DIR/$PY_FILE
