#!/bin/sh
# Redis custom entrypoint for Bug Bounty Platform
set -e

echo "Starting Redis for Bug Bounty Platform..."

# Replace environment variables in redis.conf
if [ -n "$REDIS_PASSWORD" ]; then
    echo "Setting Redis password from environment..."
    sed -i "s/\${REDIS_PASSWORD}/$REDIS_PASSWORD/g" /usr/local/etc/redis/redis.conf
else
    echo "Warning: No Redis password set, using default"
    sed -i "s/requirepass \${REDIS_PASSWORD}/# requirepass disabled/g" /usr/local/etc/redis/redis.conf
fi

# Execute the command
exec "$@"