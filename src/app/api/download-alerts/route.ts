import { NextRequest, NextResponse } from 'next/server'
import { ApiKeyService } from '@/lib/apiKeyService'
import { createClient } from '@supabase/supabase-js'

// Utility function to convert data to CSV
function convertToCSV(data: any[], headers?: string[]): string {
  if (data.length === 0) return ''

  // If no headers provided, use object keys from first item
  const csvHeaders = headers || Object.keys(data[0])

  // Create CSV header row
  const csvRows = [csvHeaders.join(',')]

  // Create data rows
  for (const item of data) {
    const row = csvHeaders.map(header => {
      const value = item[header]
      if (value === null || value === undefined) return ''

      // Escape quotes and wrap in quotes if contains comma, quote, or newline
      const stringValue = String(value)
      if (stringValue.includes(',') || stringValue.includes('"') || stringValue.includes('\n')) {
        return `"${stringValue.replace(/"/g, '""')}"`
      }
      return stringValue
    })
    csvRows.push(row.join(','))
  }

  return csvRows.join('\n')
}

// Format alerts/anomalies for API response
function formatAlertForExport(alert: any, includeEvidence = true) {
  return {
    id: alert.id,
    session_id: alert.session_id,
    user_id: alert.user_id,
    anomaly_id: alert.anomaly_id,
    type: alert.type,
    severity: alert.severity,
    title: alert.title,
    description: alert.description || alert.message,
    source_user: alert.source_user,
    source_ip: alert.source_ip,
    target_computer: alert.target_computer,
    confidence_score: alert.confidence_score,
    risk_score: alert.risk_score,
    status: alert.status,
    read: alert.read,
    archived: alert.archived,
    category: alert.category,
    rule_id: alert.rule_id,
    rule_name: alert.rule_name,
    affected_entities: alert.affected_entities,
    time_window_start: alert.time_window_start || alert.time_window?.start,
    time_window_end: alert.time_window_end || alert.time_window?.end,
    timestamp: alert.timestamp,
    detected_at: alert.detected_at || alert.created_at,
    created_at: alert.created_at,
    updated_at: alert.updated_at,
    ...(includeEvidence && {
      evidence: alert.evidence,
      metadata: alert.metadata,
      recommendations: alert.recommendations,
      context: alert.context
    })
  }
}

export async function GET(request: NextRequest) {
  try {
    // Anonymous mode - no API key required
    const userId = 'anonymous'

    // Parse query parameters
    const url = new URL(request.url)
    const format = url.searchParams.get('format') || 'json' // json or csv
    const sessionId = url.searchParams.get('session_id')
    const startDate = url.searchParams.get('start_date')
    const endDate = url.searchParams.get('end_date')
    const severity = url.searchParams.get('severity') // comma-separated list
    const status = url.searchParams.get('status') // comma-separated list
    const type = url.searchParams.get('type') // comma-separated list
    const category = url.searchParams.get('category') // comma-separated list
    const minConfidence = url.searchParams.get('min_confidence')
    const includeEvidence = url.searchParams.get('include_evidence') !== 'false' // default true
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '1000'), 10000) // max 10k

    // Validate format
    if (!['json', 'csv'].includes(format)) {
      return NextResponse.json(
        { error: 'Invalid format. Supported: json, csv' },
        { status: 400 }
      )
    }

    // Create admin client for database operations
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY!
    const supabase = createClient(supabaseUrl, serviceRoleKey)

    // Build the query for alerts
    let alertsQuery = supabase
      .from('alerts')
      .select(`
        id,
        user_id,
        session_id,
        anomaly_id,
        type,
        title,
        message,
        read,
        archived,
        metadata,
        created_at,
        anomalies (
          id,
          type,
          severity,
          title,
          description,
          source_user,
          source_ip,
          target_computer,
          evidence,
          confidence_score,
          risk_score,
          status,
          created_at,
          updated_at
        )
      `)
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(limit)

    // Apply filters
    if (sessionId) {
      alertsQuery = alertsQuery.eq('session_id', sessionId)
    }

    if (startDate) {
      alertsQuery = alertsQuery.gte('created_at', startDate)
    }

    if (endDate) {
      alertsQuery = alertsQuery.lte('created_at', endDate)
    }

    if (status) {
      const statusList = status.split(',').map(s => s.trim())
      alertsQuery = alertsQuery.in('status', statusList)
    }

    if (type) {
      const typeList = type.split(',').map(t => t.trim())
      alertsQuery = alertsQuery.in('type', typeList)
    }

    // Execute alerts query
    const { data: alertsData, error: alertsError } = await alertsQuery

    if (alertsError) {
      console.error('Alerts query error:', alertsError)
      return NextResponse.json(
        { error: 'Failed to fetch alerts' },
        { status: 500 }
      )
    }

    // Also query anomalies directly (for anomalies that might not have alerts)
    let anomaliesQuery = supabase
      .from('anomalies')
      .select(`
        id,
        session_id,
        type,
        severity,
        title,
        description,
        source_user,
        source_ip,
        target_computer,
        evidence,
        confidence_score,
        risk_score,
        status,
        created_at,
        updated_at
      `)
      .limit(limit)

    // Apply the same filters to anomalies
    if (sessionId) {
      anomaliesQuery = anomaliesQuery.eq('session_id', sessionId)
    }

    if (startDate) {
      anomaliesQuery = anomaliesQuery.gte('created_at', startDate)
    }

    if (endDate) {
      anomaliesQuery = anomaliesQuery.lte('created_at', endDate)
    }

    if (severity) {
      const severityList = severity.split(',').map(s => s.trim())
      anomaliesQuery = anomaliesQuery.in('severity', severityList)
    }

    if (status) {
      const statusList = status.split(',').map(s => s.trim())
      anomaliesQuery = anomaliesQuery.in('status', statusList)
    }

    if (type) {
      const typeList = type.split(',').map(t => t.trim())
      anomaliesQuery = anomaliesQuery.in('type', typeList)
    }

    if (minConfidence) {
      const minConf = parseFloat(minConfidence)
      if (!isNaN(minConf)) {
        anomaliesQuery = anomaliesQuery.gte('confidence_score', minConf)
      }
    }

    const { data: anomaliesData, error: anomaliesError } = await anomaliesQuery

    if (anomaliesError) {
      console.error('Anomalies query error:', anomaliesError)
      return NextResponse.json(
        { error: 'Failed to fetch anomalies' },
        { status: 500 }
      )
    }

    // Combine and format data
    const combinedData = []

    // Add alerts data
    if (alertsData) {
      for (const alert of alertsData) {
        const formatted = formatAlertForExport({
          ...alert,
          // Include anomaly data if available
          ...(alert.anomalies && alert.anomalies.length > 0 && {
            ...alert.anomalies[0],
            category: alert.anomalies[0]?.type,
            rule_id: 'alert-' + alert.id,
            rule_name: 'Alert System'
          })
        }, includeEvidence)
        combinedData.push(formatted)
      }
    }

    // Add anomalies data (avoid duplicates)
    if (anomaliesData) {
      const alertIds = new Set(combinedData.map(item => item.anomaly_id).filter(Boolean))

      for (const anomaly of anomaliesData) {
        if (!alertIds.has(anomaly.id)) {
          const formatted = formatAlertForExport({
            ...anomaly,
            user_id: userId,
            session_id: anomaly.session_id,
            anomaly_id: anomaly.id,
            category: anomaly.type,
            rule_id: 'anomaly-' + anomaly.id,
            rule_name: 'Analytics Engine',
            type: anomaly.type,
            read: false,
            archived: false,
            timestamp: anomaly.created_at,
            detected_at: anomaly.created_at
          }, includeEvidence)
          combinedData.push(formatted)
        }
      }
    }

    // Sort by created_at descending
    combinedData.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())

    // Apply limit after combining
    const finalData = combinedData.slice(0, limit)

    // Return appropriate format
    if (format === 'csv') {
      const csvContent = convertToCSV(finalData)

      return new NextResponse(csvContent, {
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': `attachment; filename="adt_alerts_${new Date().toISOString().split('T')[0]}.csv"`
        }
      })
    } else {
      // JSON format
      return NextResponse.json({
        success: true,
        count: finalData.length,
        data: finalData,
        metadata: {
          user_id: userId,
          filters_applied: {
            session_id: sessionId,
            start_date: startDate,
            end_date: endDate,
            severity,
            status,
            type,
            category,
            min_confidence: minConfidence
          },
          exported_at: new Date().toISOString(),
          format: 'json'
        }
      })
    }

  } catch (error) {
    console.error('Download alerts error:', error)
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
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-API-Key, Authorization',
    },
  })
}
