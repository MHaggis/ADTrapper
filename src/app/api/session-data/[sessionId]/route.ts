import { NextRequest, NextResponse } from 'next/server';
import { Pool } from 'pg';

// Create database connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false,
});

export async function GET(
  request: NextRequest,
  { params }: { params: { sessionId: string } }
) {
  try {
    const sessionId = params.sessionId;
    console.log(`Loading session data for: ${sessionId}`);

    const client = await pool.connect();

    try {
      // First, check if we have individual events or summarized data
      const eventDataResult = await client.query(`
        SELECT event_data
        FROM event_data
        WHERE session_id = $1
        ORDER BY created_at DESC
        LIMIT 1
      `, [sessionId]);

      if (eventDataResult.rows.length === 0) {
        return NextResponse.json(
          { error: 'No event data found for this session' },
          { status: 404 }
        );
      }

      const eventData = eventDataResult.rows[0].event_data;

      // Check if this is summarized data (bulk_upload) or individual events
      if (eventData && typeof eventData === 'object' && eventData.all_events) {
        // This contains ALL events - return them all
        const allEvents = Array.isArray(eventData.all_events) ? eventData.all_events : [];
        const totalEvents = eventData.total_events || allEvents.length;

        console.log(`Returning ALL ${allEvents.length} events out of ${totalEvents} total for session ${sessionId}`);

        return NextResponse.json({
          events: allEvents,
          metadata: {
            totalEvents: totalEvents,
            eventCount: allEvents.length,
            generatedAt: new Date().toISOString(),
            generatedBy: 'Database Load',
            note: 'Loaded complete dataset from database.',
            sessionInfo: {
              totalEvents: totalEvents,
              loadedCount: allEvents.length
            }
          }
        });
      } else if (eventData && typeof eventData === 'object' && eventData.sample_events) {
        // Fallback to sample events if all_events not available
        const sampleEvents = Array.isArray(eventData.sample_events) ? eventData.sample_events : [];
        const totalEvents = eventData.total_events || sampleEvents.length;

        console.log(`Returning ${sampleEvents.length} sample events out of ${totalEvents} total for session ${sessionId}`);

        return NextResponse.json({
          events: sampleEvents,
          metadata: {
            totalEvents: totalEvents,
            eventCount: sampleEvents.length,
            generatedAt: new Date().toISOString(),
            generatedBy: 'Database Load',
            note: 'Showing sample events. Full dataset available in analytics.',
            sessionInfo: {
              totalEvents: totalEvents,
              sampleCount: sampleEvents.length
            }
          }
        });
      } else if (eventData && typeof eventData === 'object' && eventData.metadata) {
        // Fallback to metadata-only format
        const metadata = eventData.metadata;
        console.log(`Returning metadata-only for session ${sessionId}:`, metadata);

        return NextResponse.json({
          events: [],
          metadata: {
            totalEvents: metadata.eventCount || 0,
            eventCount: 0,
            generatedAt: new Date().toISOString(),
            generatedBy: 'Database Load',
            note: 'Session data is summarized. Use analytics for detailed analysis.',
            sessionInfo: {
              fileName: metadata.fileName,
              generatedAt: metadata.generatedAt,
              generatedBy: metadata.generatedBy
            }
          }
        });
      } else {
        // This might be individual events (legacy format)
        console.log(`Returning event data for session ${sessionId}`);
        return NextResponse.json({
          events: Array.isArray(eventData) ? eventData : [eventData],
          metadata: {
            eventCount: Array.isArray(eventData) ? eventData.length : 1,
            generatedAt: new Date().toISOString(),
            generatedBy: 'Database Load'
          }
        });
      }

    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Database error:', error);
    return NextResponse.json(
      { error: 'Failed to load session data' },
      { status: 500 }
    );
  }
}
