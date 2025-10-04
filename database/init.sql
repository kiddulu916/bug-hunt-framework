-- Database initialization script for Bug Bounty Automation Platform

-- Create database if it doesn't exist
SELECT 'CREATE DATABASE bug_hunt_db'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'bug_hunt_db')\gexec

-- Connect to the database
\c bug_hunt_db;

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Create custom types for better performance
DO $$
BEGIN
    -- Severity enum
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'severity_enum') THEN
        CREATE TYPE severity_enum AS ENUM ('critical', 'high', 'medium', 'low', 'info');
    END IF;

    -- Scan status enum
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'scan_status_enum') THEN
        CREATE TYPE scan_status_enum AS ENUM ('queued', 'running', 'paused', 'completed', 'failed', 'cancelled');
    END IF;

    -- Platform enum
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'platform_enum') THEN
        CREATE TYPE platform_enum AS ENUM ('hackerone', 'bugcrowd', 'intigriti', 'synack', 'yeswehack', 'private');
    END IF;
END$$;

-- Create indexes for better query performance
DO $$
BEGIN
    -- This will be executed after tables are created by Django/SQLAlchemy migrations
    -- Adding performance optimization queries for when tables exist

    -- Function to create indexes if tables exist
    CREATE OR REPLACE FUNCTION create_performance_indexes() RETURNS void AS $func$
    BEGIN
        -- Targets table indexes
        IF EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'targets') THEN
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_targets_platform ON targets(platform);
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_targets_active ON targets(is_active);
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_targets_name_trgm ON targets USING gin(target_name gin_trgm_ops);
        END IF;

        -- Scan sessions indexes
        IF EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'scan_sessions') THEN
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_sessions_status ON scan_sessions(status);
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_sessions_target_status ON scan_sessions(target_id, status);
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_sessions_created ON scan_sessions(created_at DESC);
        END IF;

        -- Vulnerabilities indexes
        IF EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'vulnerabilities') THEN
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerabilities_scan_severity ON vulnerabilities(scan_session_id, severity);
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerabilities_type ON vulnerabilities(vulnerability_type);
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerabilities_verified ON vulnerabilities(manually_verified);
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerabilities_url_trgm ON vulnerabilities USING gin(affected_url gin_trgm_ops);
        END IF;

        -- Recon results indexes
        IF EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'recon_results') THEN
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_recon_results_type ON recon_results(result_type);
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_recon_results_scope ON recon_results(is_in_scope);
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_recon_results_asset_trgm ON recon_results USING gin(discovered_asset gin_trgm_ops);
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_recon_results_scan_type ON recon_results(scan_session_id, result_type);
        END IF;

        -- Tool executions indexes
        IF EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'tool_executions') THEN
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tool_executions_name ON tool_executions(tool_name);
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tool_executions_status ON tool_executions(status);
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tool_executions_scan_tool ON tool_executions(scan_session_id, tool_name);
        END IF;
    END
    $func$ LANGUAGE plpgsql;
END$$;

-- Create a function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE bug_hunt_db TO postgres;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO postgres;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO postgres;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO postgres;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO postgres;

-- Performance settings
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET track_activity_query_size = 2048;
ALTER SYSTEM SET pg_stat_statements.track = 'all';
ALTER SYSTEM SET log_min_duration_statement = 1000;
ALTER SYSTEM SET log_checkpoints = on;
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;
ALTER SYSTEM SET log_statement = 'mod';

-- Configuration for better performance with scanning workloads
ALTER SYSTEM SET work_mem = '32MB';
ALTER SYSTEM SET maintenance_work_mem = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET random_page_cost = 1.1;

COMMIT;

-- Instructions for running performance indexes after migrations
\echo 'Run the following command after Django/SQLAlchemy migrations:'
\echo 'SELECT create_performance_indexes();'