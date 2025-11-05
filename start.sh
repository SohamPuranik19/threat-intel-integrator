#!/bin/bash
cd /opt/render/project/src
export PYTHONPATH=/opt/render/project/src:$PYTHONPATH
exec python -m uvicorn infosecwriteups.api_server_enhanced:app --host 0.0.0.0 --port "$PORT"
