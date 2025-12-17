#!/bin/sh
set -e

# Ensure directory is writable
chmod 777 /data

# Set umask so created files are group/world readable/writable
umask 0000

# Execute the main command
exec "$@"
