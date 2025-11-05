#!/bin/bash
set -e
cd /opt/render/project/src
export PYTHONPATH=/opt/render/project/src:$PYTHONPATH
echo "Current directory: $(pwd)"
echo "PYTHONPATH: $PYTHONPATH"
echo "Python version: $(python3 --version)"
echo "Checking if module exists..."
ls -la infosecwriteups/
exec python3 -m uvicorn infosecwriteups.api_server_enhanced:app --host 0.0.0.0 --port "$PORT"
