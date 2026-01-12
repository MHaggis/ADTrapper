import { NextRequest, NextResponse } from 'next/server';
import { Pool } from 'pg';

// Create database connection pool using DATABASE_URL or individual params
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

export async function GET(request: NextRequest) {
  try {
    const client = await pool.connect();

    try {
      const result = await client.query(`
        SELECT
          id,
          session_name,
          file_name,
          file_size_bytes,
          event_count,
          anomaly_count,
          uploaded_at,
          time_range_start,
          time_range_end,
          storage_path
        FROM analysis_sessions
        ORDER BY uploaded_at DESC
      `);

      // Transform the data to match the expected format
      const sessions = result.rows.map(row => ({
        id: row.id,
        user_id: 'anonymous',
        session_name: row.session_name,
        uploaded_at: row.uploaded_at,
        file_name: row.file_name,
        file_size: row.file_size_bytes,
        event_count: row.event_count,
        anomaly_count: row.anomaly_count,
        time_range_start: row.time_range_start,
        time_range_end: row.time_range_end,
        storage_path: row.storage_path
      }));

      return NextResponse.json({ sessions });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Database error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch sessions' },
      { status: 500 }
    );
  }
}
