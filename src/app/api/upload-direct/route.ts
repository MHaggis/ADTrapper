import { NextRequest, NextResponse } from 'next/server';
import { Pool } from 'pg';

// Create a connection pool for PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 20
});

// Handle database connection errors gracefully
pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
  process.exit(-1);
});

export async function POST(request: NextRequest) {
  try {
    // Handle JSON data instead of FormData
    const body = await request.json();
    const { sessionData, eventData } = body;

    if (!sessionData) {
      return NextResponse.json({ error: 'No session data provided' }, { status: 400 });
    }

    console.log(`Processing upload: ${sessionData.file_name}, size: ${sessionData.file_size_bytes} bytes`);

    // Extract events from the eventData provided
    let events: any[] = [];
    if (eventData && eventData.event_data && eventData.event_data.sample_events) {
      events = eventData.event_data.sample_events;
    }

    if (events.length === 0) {
      return NextResponse.json({
        error: 'No events found in file'
      }, { status: 400 });
    }

          console.log(`Found ${events.length} events in upload`);

      // Start database transaction
      const client = await pool.connect();

      try {
        await client.query('BEGIN');

        // Generate session ID
        const sessionId = crypto.randomUUID();

        // Insert session record using provided sessionData
        const sessionResult = await client.query(`
          INSERT INTO analysis_sessions (
            id, session_name, uploaded_at, file_name, file_size_bytes,
            event_count, anomaly_count, time_range_start, time_range_end, storage_path, created_at
          ) VALUES ($1, $2, NOW(), $3, $4, $5, $6, $7, $8, $9, NOW())
          RETURNING id
        `, [
          sessionId,
          sessionData.session_name,
          sessionData.file_name,
          sessionData.file_size_bytes,
          sessionData.event_count,
          sessionData.anomaly_count,
          sessionData.time_range_start,
          sessionData.time_range_end,
          sessionData.storage_path
        ]);

      // Insert the summarized event data
      await client.query(`
        INSERT INTO event_data (
          session_id, event_type, event_data, timestamp,
          source_ip, destination_ip, username, computer_name, event_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      `, [
        sessionId,
        eventData.event_type,
        eventData.event_data,
        eventData.timestamp,
        eventData.source_ip,
        eventData.destination_ip,
        eventData.username,
        eventData.computer_name,
        eventData.event_id
      ]);

      console.log(`Inserted summarized event data for session ${sessionId}`);

      // Update session with anomaly count (placeholder for now)
      await client.query(`
        UPDATE analysis_sessions
        SET anomaly_count = 0
        WHERE id = $1
      `, [sessionId]);

      await client.query('COMMIT');

      console.log(`Successfully uploaded session ${sessionId} with ${events.length} events`);

      // Return session data in expected format
      const session = {
        id: sessionId,
        session_name: sessionData.session_name,
        file_name: sessionData.file_name,
        file_size_bytes: sessionData.file_size_bytes,
        event_count: sessionData.event_count,
        anomaly_count: sessionData.anomaly_count,
        uploaded_at: new Date().toISOString(),
        time_range_start: sessionData.time_range_start,
        time_range_end: sessionData.time_range_end,
        storage_path: sessionData.storage_path
      };

      return NextResponse.json({
        success: true,
        session,
        eventCount: events.length,
        message: `Successfully uploaded ${events.length} events`
      });

    } catch (dbError) {
      await client.query('ROLLBACK');
      console.error('Database error during upload:', dbError);
      return NextResponse.json({
        error: 'Database error during upload',
        details: dbError instanceof Error ? dbError.message : 'Unknown database error'
      }, { status: 500 });
    } finally {
      client.release();
    }

  } catch (error) {
    console.error('Upload error:', error);
    return NextResponse.json({
      error: 'Upload failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 });
  }
}

export async function GET() {
  return NextResponse.json({
    message: 'ADTrapper Upload Direct API',
    status: 'running',
    timestamp: new Date().toISOString()
  });
}
