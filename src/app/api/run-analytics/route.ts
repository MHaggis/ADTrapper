import { NextRequest, NextResponse } from 'next/server'
import { FileUploadService } from '@/lib/fileUploadService'
import { AnalyticsEngine } from '@/analytics/AnalyticsEngine'

export async function POST(request: NextRequest) {
  try {
    const { sessionId } = await request.json()

    if (!sessionId) {
      return NextResponse.json({ error: 'Session ID required' }, { status: 400 })
    }

    // Get session from database using service role
    const { createClient } = require('@supabase/supabase-js');
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY!;
    const adminSupabase = createClient(supabaseUrl, serviceRoleKey);

    const { data: session, error: sessionError } = await adminSupabase
      .from('analysis_sessions')
      .select('*')
      .eq('id', sessionId)
      .single();

    if (sessionError) {
      return NextResponse.json({ error: `Session not found: ${sessionError.message}` }, { status: 404 })
    }

    // Load session data
    console.log('Loading session data for analytics...');
    const sessionData = await FileUploadService.loadSessionData(session);
    
    if (!sessionData || !sessionData.events || sessionData.events.length === 0) {
      return NextResponse.json({ 
        error: 'No events found in session',
        debug: {
          hasSessionData: !!sessionData,
          hasEvents: !!sessionData?.events,
          eventCount: sessionData?.events?.length || 0,
          isChunked: session.storage_path.startsWith('chunked:')
        }
      }, { status: 400 })
    }

    // Run analytics
    console.log(`Running analytics on ${sessionData.events.length} events...`);
    const analyticsEngine = new AnalyticsEngine();
    const context = {
      sessionId: sessionId,
      organizationId: 'test',
      timeRange: {
        start: new Date(Date.now() - 24 * 60 * 60 * 1000),
        end: new Date()
      }
    };

    const analysisResult = await analyticsEngine.analyze(sessionData.events, context);
    
    // Update session with anomaly count
    await adminSupabase
      .from('analysis_sessions')
      .update({ anomaly_count: analysisResult.anomalies.length })
      .eq('id', sessionId);

    return NextResponse.json({
      success: true,
      sessionId: sessionId,
      eventCount: sessionData.events.length,
      anomaliesFound: analysisResult.anomalies.length,
      rulesExecuted: analysisResult.summary.totalRulesExecuted,
      anomalies: analysisResult.anomalies.slice(0, 5) // First 5 for debugging
    })

  } catch (error) {
    console.error('Analytics test error:', error)
    return NextResponse.json({ 
      error: error instanceof Error ? error.message : 'Internal server error',
      stack: error instanceof Error ? error.stack : undefined
    }, { status: 500 })
  }
}
