-- =============================================================================
-- ADTrapper Simple Database Setup (No Authentication)
-- =============================================================================

-- =============================================================================
-- STEP 1: CREATE EXTENSIONS
-- =============================================================================

-- Create necessary extensions (with superuser privileges)
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'uuid-ossp extension already exists or cannot be created';
END $$;

DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS pgcrypto;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pgcrypto extension already exists or cannot be created';
END $$;

-- =============================================================================
-- STEP 2: CREATE ROLES AND USERS
-- =============================================================================

-- Create anon role for PostgREST
DO $$
BEGIN
    CREATE ROLE anon;
EXCEPTION WHEN DUPLICATE_OBJECT THEN
    RAISE NOTICE 'anon role already exists';
END $$;

-- Create postgrest user if it doesn't exist
DO $$
BEGIN
    CREATE USER postgrest WITH PASSWORD 'postgrest123';
EXCEPTION WHEN DUPLICATE_OBJECT THEN
    RAISE NOTICE 'postgrest user already exists';
END $$;

-- =============================================================================
-- STEP 3: CREATE TABLES
-- =============================================================================

-- Analysis Sessions Table (anonymous uploads)
CREATE TABLE IF NOT EXISTS analysis_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_name TEXT NOT NULL,
    uploaded_at TIMESTAMPTZ DEFAULT NOW(),
    file_name TEXT,
    file_size_bytes BIGINT,
    event_count INTEGER,
    anomaly_count INTEGER,
    time_range_start TIMESTAMPTZ,
    time_range_end TIMESTAMPTZ,
    storage_path TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Event Data Table (for storing parsed event data)
CREATE TABLE IF NOT EXISTS event_data (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID REFERENCES analysis_sessions(id) ON DELETE CASCADE,
    event_type TEXT,
    event_data JSONB,
    timestamp TIMESTAMPTZ,
    source_ip TEXT,
    destination_ip TEXT,
    username TEXT,
    computer_name TEXT,
    event_id INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Analysis Results Table
CREATE TABLE IF NOT EXISTS analysis_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID REFERENCES analysis_sessions(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    event_data JSONB,
    findings JSONB,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Feedback Table (anonymous feedback)
CREATE TABLE IF NOT EXISTS feedback (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID REFERENCES analysis_sessions(id) ON DELETE SET NULL,
    rating INTEGER CHECK (rating >= 1 AND rating <= 5),
    feedback_text TEXT,
    is_bug_report BOOLEAN DEFAULT FALSE,
    contact_email TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================================================
-- STEP 4: CREATE INDEXES
-- =============================================================================

-- Analysis Sessions indexes
CREATE INDEX IF NOT EXISTS idx_analysis_sessions_uploaded_at ON analysis_sessions(uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_sessions_session_name ON analysis_sessions(session_name);

-- Event Data indexes
CREATE INDEX IF NOT EXISTS idx_event_data_session_id ON event_data(session_id);
CREATE INDEX IF NOT EXISTS idx_event_data_timestamp ON event_data(timestamp);
CREATE INDEX IF NOT EXISTS idx_event_data_event_type ON event_data(event_type);

-- Analysis Results indexes
CREATE INDEX IF NOT EXISTS idx_analysis_results_session_id ON analysis_results(session_id);
CREATE INDEX IF NOT EXISTS idx_analysis_results_rule_id ON analysis_results(rule_id);
CREATE INDEX IF NOT EXISTS idx_analysis_results_severity ON analysis_results(severity);
CREATE INDEX IF NOT EXISTS idx_analysis_results_timestamp ON analysis_results(timestamp DESC);

-- =============================================================================
-- STEP 5: CREATE FUNCTIONS
-- =============================================================================

-- Function to clean up old anonymous sessions (older than 30 days)
CREATE OR REPLACE FUNCTION cleanup_old_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM analysis_sessions 
    WHERE uploaded_at < NOW() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;

-- Function to get session summary
CREATE OR REPLACE FUNCTION get_session_summary(session_uuid UUID)
RETURNS TABLE(
    session_name TEXT,
    file_name TEXT,
    event_count INTEGER,
    anomaly_count INTEGER,
    high_severity_count BIGINT,
    medium_severity_count BIGINT,
    low_severity_count BIGINT,
    uploaded_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        s.session_name,
        s.file_name,
        s.event_count,
        s.anomaly_count,
        COUNT(r.id) FILTER (WHERE r.severity = 'high') as high_severity_count,
        COUNT(r.id) FILTER (WHERE r.severity = 'medium') as medium_severity_count,
        COUNT(r.id) FILTER (WHERE r.severity = 'low') as low_severity_count,
        s.uploaded_at
    FROM analysis_sessions s
    LEFT JOIN analysis_results r ON s.id = r.session_id
    WHERE s.id = session_uuid
    GROUP BY s.id, s.session_name, s.file_name, s.event_count, s.anomaly_count, s.uploaded_at;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 6: CREATE VIEWS
-- =============================================================================

-- Recent sessions view
CREATE OR REPLACE VIEW recent_sessions AS
SELECT 
    id,
    session_name,
    file_name,
    event_count,
    anomaly_count,
    uploaded_at,
    (SELECT COUNT(*) FROM analysis_results WHERE session_id = analysis_sessions.id) as total_findings
FROM analysis_sessions
ORDER BY uploaded_at DESC
LIMIT 100;

-- Session statistics view
CREATE OR REPLACE VIEW session_stats AS
SELECT 
    DATE_TRUNC('day', uploaded_at) as upload_date,
    COUNT(*) as sessions_count,
    SUM(event_count) as total_events,
    SUM(anomaly_count) as total_anomalies,
    AVG(file_size_bytes) as avg_file_size
FROM analysis_sessions
WHERE uploaded_at >= NOW() - INTERVAL '30 days'
GROUP BY DATE_TRUNC('day', uploaded_at)
ORDER BY upload_date DESC;

-- =============================================================================
-- STEP 7: PERMISSIONS
-- =============================================================================

-- Grant permissions to postgres user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO postgres;

-- Grant permissions to anon role (for PostgREST)
GRANT USAGE ON SCHEMA public TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO anon;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO anon;

-- Grant permissions to postgrest user
GRANT USAGE ON SCHEMA public TO postgrest;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO postgrest;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO postgrest;

-- Make anon role a member of postgrest user
GRANT anon TO postgrest;

-- =============================================================================
-- DONE!
-- =============================================================================

-- Insert a welcome message
INSERT INTO analysis_sessions (session_name, file_name, event_count, anomaly_count, storage_path)
VALUES ('Welcome to ADTrapper', 'README.txt', 0, 0, '/welcome')
ON CONFLICT DO NOTHING;

DO $$
BEGIN
    RAISE NOTICE 'ADTrapper database setup complete! No authentication required - ready for anonymous uploads.';
END $$;
