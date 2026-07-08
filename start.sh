#!/bin/sh
# Restore DB from S3 if a replica exists (no-op on first run)
litestream restore -if-replica-exists -config /app/litestream.yml /data/sentinelai.db || true
# Start replication + app together
exec litestream replicate -config /app/litestream.yml \
    -exec "uvicorn sentinelai.api.main:app --host 0.0.0.0 --port 8000"
