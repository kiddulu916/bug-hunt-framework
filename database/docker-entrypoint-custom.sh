#!/bin/bash
set -e

# Custom entrypoint script for PostgreSQL with bug bounty platform optimizations

echo "Starting PostgreSQL with custom configuration for Bug Bounty Platform..."

# Execute the original PostgreSQL docker-entrypoint.sh
exec docker-entrypoint.sh "$@"