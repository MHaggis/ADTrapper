import { NextRequest, NextResponse } from 'next/server';
import { Pool } from 'pg';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false,
});

export async function DELETE(
  request: NextRequest,
  { params }: { params: { sessionId: string } }
) {
  const { sessionId } = params;

  try {
    console.log(`Deleting session: ${sessionId}`);

    // First, delete event_data records
    await pool.query('DELETE FROM event_data WHERE session_id = $1', [sessionId]);

    // Then, delete analysis_results records
    await pool.query('DELETE FROM analysis_results WHERE session_id = $1', [sessionId]);

    // Finally, delete the session itself
    const result = await pool.query(
      'DELETE FROM analysis_sessions WHERE id = $1 RETURNING *',
      [sessionId]
    );

    if (result.rowCount === 0) {
      return NextResponse.json(
        { error: 'Session not found' },
        { status: 404 }
      );
    }

    console.log(`Successfully deleted session: ${sessionId}`);

    return NextResponse.json({
      success: true,
      message: 'Session deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting session:', error);
    return NextResponse.json(
      { error: 'Failed to delete session' },
      { status: 500 }
    );
  }
}
