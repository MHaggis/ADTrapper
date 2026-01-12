import { NextRequest, NextResponse } from 'next/server'
import { FileUploadService } from '@/lib/fileUploadService'
import { AnalyticsEngine } from '@/analytics/AnalyticsEngine'

export async function POST(request: NextRequest) {
  try {
    // Anonymous mode - no API key required
    const userId = 'anonymous'

    // Parse form data
    const formData = await request.formData()
    const files = formData.getAll('files') as File[]
    const sessionName = formData.get('sessionName') as string || `API Upload ${new Date().toISOString()}`

    if (!files || files.length === 0) {
      return NextResponse.json(
        { error: 'No files provided. Use "files" field to upload files.' },
        { status: 400 }
      )
    }

    // Process files (similar to the web upload)
    const processedFiles = await Promise.all(
      files.map(async (file, index) => {
        // Convert File to the format expected by FileUploadService
        const fileContent = await file.arrayBuffer()
        const fileName = file.name || `uploaded_file_${index + 1}.json`

        return {
          name: fileName,
          content: fileContent,
          size: file.size,
          type: file.type
        }
      })
    )

    // Upload and process the files
    const uploadResult = await FileUploadService.processApiUpload(
      processedFiles,
      userId,
      sessionName
    )

    // Run analytics on the uploaded data (same as web upload)
    let anomaliesFound = 0;
    try {
      // Get session from database to get storage path
      const { createClient } = require('@supabase/supabase-js');
      const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
      const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY!;
      const adminSupabase = createClient(supabaseUrl, serviceRoleKey);

      const { data: session, error: sessionError } = await adminSupabase
        .from('analysis_sessions')
        .select('*')
        .eq('id', uploadResult.sessionId)
        .single();

      if (sessionError) {
        throw new Error(`Failed to get session: ${sessionError.message}`);
      }

      // Load the uploaded session data to get events
      const sessionData = await FileUploadService.loadSessionData(session);

      if (sessionData && sessionData.events && sessionData.events.length > 0) {
        const analyticsEngine = new AnalyticsEngine();
        const context = {
          sessionId: uploadResult.sessionId,
          organizationId: 'api-upload',
          timeRange: {
            start: new Date(Date.now() - 24 * 60 * 60 * 1000),
            end: new Date()
          }
        };

        const analysisResult = await analyticsEngine.analyze(sessionData.events, context);
        anomaliesFound = analysisResult.anomalies.length;

        // Update session with anomaly count using service role
        await adminSupabase
          .from('analysis_sessions')
          .update({ anomaly_count: anomaliesFound })
          .eq('id', uploadResult.sessionId);
      }
    } catch (analyticsError) {
      console.error('Analytics processing failed:', analyticsError instanceof Error ? analyticsError.message : 'Unknown error');
      // Don't fail the upload if analytics fails
    }

    return NextResponse.json({
      success: true,
      message: `Successfully uploaded ${files.length} file(s)`,
      sessionId: uploadResult.sessionId,
      filesProcessed: files.length,
      totalEvents: uploadResult.totalEvents,
      anomaliesFound: anomaliesFound
    })

  } catch (error) {
    console.error('API upload failed:', error instanceof Error ? error.message : 'Unknown error')
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}

// Handle preflight requests for CORS
export async function OPTIONS() {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-API-Key, Authorization',
    },
  })
}
