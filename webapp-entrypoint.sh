#!/bin/sh
set -e

# Ensure database file has correct permissions if it exists
if [ -f /data/taprofiler.db ]; then
    chmod 666 /data/taprofiler.db
fi

# Ensure directory is writable
chmod 777 /data

# Execute the main command
exec "$@"
