# Redis Dockerfile - Optimized for Bug Bounty Platform
FROM redis:7-alpine

# Install additional tools for monitoring and debugging
RUN apk add --no-cache \
    curl \
    netcat-openbsd \
    && rm -rf /var/cache/apk/*

# Copy custom Redis configuration
COPY redis.conf /usr/local/etc/redis/redis.conf
COPY redis-entrypoint.sh /usr/local/bin/redis-entrypoint.sh

# Make entrypoint executable
RUN chmod +x /usr/local/bin/redis-entrypoint.sh

# Create data directory
RUN mkdir -p /data

# Expose Redis port
EXPOSE 6379

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD redis-cli --raw incr ping || exit 1

# Use custom entrypoint
ENTRYPOINT ["/usr/local/bin/redis-entrypoint.sh"]

# Default command
CMD ["redis-server", "/usr/local/etc/redis/redis.conf"]