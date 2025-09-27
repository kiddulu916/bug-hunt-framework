# Database Dockerfile - PostgreSQL with Custom Extensions
FROM postgres:15-alpine

# Install additional extensions and utilities
RUN apk add --no-cache \
    postgresql-contrib \
    postgresql-dev \
    build-base \
    && rm -rf /var/cache/apk/*

# Copy initialization scripts
COPY init.sql /docker-entrypoint-initdb.d/01-init.sql
COPY migrations/ /docker-entrypoint-initdb.d/migrations/

# Set PostgreSQL configuration for performance
RUN echo "shared_preload_libraries = 'pg_stat_statements'" >> /usr/local/share/postgresql/postgresql.conf.sample
RUN echo "max_connections = 200" >> /usr/local/share/postgresql/postgresql.conf.sample
RUN echo "shared_buffers = 256MB" >> /usr/local/share/postgresql/postgresql.conf.sample
RUN echo "effective_cache_size = 1GB" >> /usr/local/share/postgresql/postgresql.conf.sample
RUN echo "work_mem = 32MB" >> /usr/local/share/postgresql/postgresql.conf.sample
RUN echo "maintenance_work_mem = 256MB" >> /usr/local/share/postgresql/postgresql.conf.sample
RUN echo "random_page_cost = 1.1" >> /usr/local/share/postgresql/postgresql.conf.sample
RUN echo "effective_io_concurrency = 200" >> /usr/local/share/postgresql/postgresql.conf.sample
RUN echo "checkpoint_completion_target = 0.9" >> /usr/local/share/postgresql/postgresql.conf.sample
RUN echo "wal_buffers = 16MB" >> /usr/local/share/postgresql/postgresql.conf.sample
RUN echo "default_statistics_target = 100" >> /usr/local/share/postgresql/postgresql.conf.sample

# Set timezone
ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Create custom entrypoint script for additional setup
COPY docker-entrypoint-custom.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint-custom.sh

# Expose port
EXPOSE 5432

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=60s --retries=3 \
    CMD pg_isready -U $POSTGRES_USER -d $POSTGRES_DB

# Use custom entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint-custom.sh"]
CMD ["postgres"]