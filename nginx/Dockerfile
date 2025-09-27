# Nginx Dockerfile - Reverse Proxy for Bug Bounty Platform
FROM nginx:alpine

# Install additional utilities
RUN apk add --no-cache \
    curl \
    certbot \
    certbot-nginx \
    && rm -rf /var/cache/apk/*

# Remove default nginx configuration
RUN rm /etc/nginx/conf.d/default.conf

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf
COPY conf.d/ /etc/nginx/conf.d/

# Create necessary directories
RUN mkdir -p /var/www/static /var/www/media /var/www/reports
RUN mkdir -p /etc/nginx/ssl
RUN mkdir -p /var/log/nginx

# Create nginx user and set permissions
RUN chown -R nginx:nginx /var/www /var/log/nginx /etc/nginx

# Copy custom error pages
COPY error-pages/ /usr/share/nginx/html/ 2>/dev/null || true

# Create SSL directory for certificates
RUN mkdir -p /etc/letsencrypt

# Add health check endpoint
RUN echo 'server { listen 80; location /nginx-health { access_log off; return 200 "healthy\n"; add_header Content-Type text/plain; } }' > /etc/nginx/conf.d/health.conf

# Set proper permissions
RUN chmod 755 /etc/nginx/conf.d/health.conf

# Expose ports
EXPOSE 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/nginx-health || exit 1

# Start nginx in foreground
CMD ["nginx", "-g", "daemon off;"]