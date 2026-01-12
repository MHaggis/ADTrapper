import { NextRequest, NextResponse } from 'next/server';
import { Pool } from 'pg';

// Create database connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false,
});

export async function PUT(request: NextRequest) {
  try {
    const body = await request.json();
    const { sessionId, anomalyCount } = body;

    if (!sessionId || typeof anomalyCount !== 'number') {
      return NextResponse.json(
        { error: 'sessionId and anomalyCount are required' },
        { status: 400 }
      );
    }

    console.log(`Updating session ${sessionId} with ${anomalyCount} anomalies`);

    const client = await pool.connect();

    try {
      const result = await client.query(`
        UPDATE analysis_sessions
        SET anomaly_count = $1
        WHERE id = $2
        RETURNING id, session_name, anomaly_count
      `, [anomalyCount, sessionId]);

      if (result.rows.length === 0) {
        return NextResponse.json(
          { error: 'Session not found' },
          { status: 404 }
        );
      }

      console.log(`Successfully updated session ${sessionId} with ${anomalyCount} anomalies`);

      return NextResponse.json({
        success: true,
        session: result.rows[0]
      });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Database error:', error);
    return NextResponse.json(
      { error: 'Failed to update session analysis' },
      { status: 500 }
    );
  }
}
