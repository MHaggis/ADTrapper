import { useState, useCallback, useMemo, useEffect } from 'react'
import { AnalyticsEngine } from '@/analytics/AnalyticsEngine'
import { AuthEvent, AnalyticsContext, AnalyticsResult, Anomaly } from '@/analytics/types'
import { RuleConfigService } from '@/lib/ruleConfigService'
// No auth needed in anonymous mode
import SplunkHECService from '@/lib/splunkHECService'

export const useAnalytics = () => {
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [lastResult, setLastResult] = useState<AnalyticsResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [userRuleConfigs, setUserRuleConfigs] = useState<any[]>([])

  // No user needed in anonymous mode

  // Create analytics engine instance (memoized)
  const engine = useMemo(() => new AnalyticsEngine(), [])

  // Load user rule configurations
  const loadUserRuleConfigs = useCallback(async () => {
    // Load default configs for anonymous mode

    try {
      const defaultRules = engine.getRules()
      const configsWithUserSettings = await RuleConfigService.getRulesWithUserConfig('anonymous', defaultRules)
      setUserRuleConfigs(configsWithUserSettings)
    } catch (error) {
      console.error('Error loading user rule configs:', error)
      // On error, fall back to default rules
      try {
        const defaultRules = engine.getRules()
        setUserRuleConfigs(defaultRules.map(rule => ({ ...rule, isCustomized: false })))
      } catch (fallbackError) {
        console.error('Error loading fallback rules:', fallbackError)
        setUserRuleConfigs([])
      }
    }
  }, [engine])

  // Load user configs when user changes
  useEffect(() => {
    loadUserRuleConfigs()
  }, [loadUserRuleConfigs])

  /**
   * Run analytics on authentication events with user configurations
   */
  const analyzeEvents = useCallback(async (
    events: AuthEvent[],
    context: AnalyticsContext
  ): Promise<AnalyticsResult | null> => {
    setIsAnalyzing(true)
    setError(null)

    try {
      // Use user configurations if available, otherwise use default rules
      const rulesToUse = userRuleConfigs.length > 0 ? userRuleConfigs : undefined

      const result = await engine.analyze(events, context, rulesToUse)
      setLastResult(result)

      // Send anomalies to Splunk if configured
      if (result && result.anomalies && result.anomalies.length > 0) {
        await sendAnomaliesToSplunk(result.anomalies)
      }

      // Send all events to Splunk if configured for auto-send
      if (result) {
        await sendEventsToSplunk(events)
      }

      return result
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Analysis failed'
      setError(errorMessage)
      console.error('Analytics error:', err)
      return null
    } finally {
      setIsAnalyzing(false)
    }
  }, [engine, userRuleConfigs])

  /**
   * Send anomalies to Splunk HEC if configured
   */
  const sendAnomaliesToSplunk = useCallback(async (anomalies: Anomaly[]) => {
    try {
      const splunkConfig = SplunkHECService.getConfig()
      if (!splunkConfig || !splunkConfig.enabled || !splunkConfig.autoSend || !splunkConfig.sendAnomalies) {
        return // Splunk not configured or anomalies sending disabled
      }

      console.log(`Sending ${anomalies.length} anomalies to Splunk`)

      // Convert anomalies to events for Splunk
      const anomalyEvents = anomalies.map(anomaly => ({
        ...anomaly,
        eventType: 'anomaly',
        splunkTimestamp: new Date().toISOString(),
        severity: anomaly.severity,
        ruleName: anomaly.ruleName,
        confidence: anomaly.confidence,
        affectedEntities: anomaly.affectedEntities,
        evidence: anomaly.evidence,
        recommendations: anomaly.recommendations
      }))

      await SplunkHECService.sendLogs(anomalyEvents, splunkConfig)

    } catch (error) {
      console.error('Error sending anomalies to Splunk:', error)
      // Don't throw error - we don't want to break the analytics flow
    }
  }, [])

  /**
   * Send all events to Splunk HEC if configured
   */
  const sendEventsToSplunk = useCallback(async (events: AuthEvent[]) => {
    try {
      const splunkConfig = SplunkHECService.getConfig()
      if (!splunkConfig || !splunkConfig.enabled || !splunkConfig.autoSend || !splunkConfig.sendAllEvents) {
        return // Splunk not configured or all events sending disabled
      }

      console.log(`Sending ${events.length} events to Splunk`)

      // Convert events to Splunk format
      const splunkEvents = events.map(event => ({
        ...event,
        eventType: 'authentication_event',
        splunkTimestamp: new Date().toISOString(),
        analyzed_at: new Date().toISOString(),
        analysis_session: `adt-${Date.now()}`
      }))

      await SplunkHECService.sendLogs(splunkEvents, splunkConfig)

    } catch (error) {
      console.error('Error sending events to Splunk:', error)
      // Don't throw error - we don't want to break the analytics flow
    }
  }, [])

  /**
   * Run analytics for specific category
   */
  const analyzeByCategory = useCallback(async (
    events: AuthEvent[],
    context: AnalyticsContext,
    category: 'authentication' | 'network' | 'behavior' | 'privilege' | 'temporal'
  ): Promise<AnalyticsResult | null> => {
    setIsAnalyzing(true)
    setError(null)

    try {
      const result = await engine.analyzeByCategory(events, context, category)

      // Send all events to Splunk if configured for auto-send
      await sendEventsToSplunk(events)

      return result
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Category analysis failed'
      setError(errorMessage)
      return null
    } finally {
      setIsAnalyzing(false)
    }
  }, [engine])

  /**
   * Get all available rules
   */
  const getRules = useCallback(() => {
    return engine.getRules()
  }, [engine])

  /**
   * Get enabled rules
   */
  const getEnabledRules = useCallback(() => {
    return engine.getEnabledRules()
  }, [engine])

  /**
   * Enable/disable a rule
   */
  const toggleRule = useCallback((ruleId: string, enabled: boolean) => {
    if (enabled) {
      return engine.enableRule(ruleId)
    } else {
      return engine.disableRule(ruleId)
    }
  }, [engine])

  /**
   * Update rule configuration
   */
  const updateRuleConfig = useCallback((ruleId: string, config: any) => {
    return engine.updateRuleConfig(ruleId, config)
  }, [engine])

  /**
   * Test a single rule
   */
  const testRule = useCallback(async (
    ruleId: string,
    events: AuthEvent[],
    context: AnalyticsContext
  ) => {
    setIsAnalyzing(true)
    setError(null)

    try {
      const result = await engine.testRule(ruleId, events, context)
      return result
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Rule test failed'
      setError(errorMessage)
      return null
    } finally {
      setIsAnalyzing(false)
    }
  }, [engine])

  /**
   * Get analytics statistics
   */
  const getStatistics = useCallback(() => {
    return engine.getStatistics()
  }, [engine])

  /**
   * Convert sample data to proper format for analytics
   */
  const processSampleData = useCallback((sampleData: any): {
    events: AuthEvent[]
    context: AnalyticsContext
  } => {
    // Add null checks to prevent errors when sampleData is undefined
    if (!sampleData || !sampleData.edges || !Array.isArray(sampleData.edges)) {
      return {
        events: [],
        context: {
          sessionId: 'default',
          organizationId: 'default',
          timeRange: {
            start: new Date(Date.now() - 24 * 60 * 60 * 1000),
            end: new Date()
          }
        }
      };
    }

    // Convert sample edges to AuthEvents
    const events: AuthEvent[] = sampleData.edges.map((edge: any, index: number) => ({
      id: `event_${index}`,
      timestamp: new Date(edge.timestamp),
      eventId: edge.status === 'Success' ? '4624' : '4625',
      computerName: edge.target?.replace('computer_', ''),
      userName: edge.source?.replace('user_', ''),
      domainName: 'COMPANY',
      sourceIp: edge.source?.startsWith('ip_') ? edge.source.replace('ip_', '') : undefined,
      logonType: edge.logonType || 'Interactive',
      status: edge.status,
      failureReason: edge.status === 'Failed' ? 'Bad username or password' : undefined
    }))

    // Create context from sample data
    const context: AnalyticsContext = {
      sessionId: 'sample_session',
      organizationId: 'sample_org',
      timeRange: {
        start: new Date(Date.now() - 24 * 60 * 60 * 1000), // 24 hours ago
        end: new Date()
      },
      userProfiles: sampleData.nodes
        .filter((node: any) => node.type === 'user')
        .map((node: any) => ({
          userName: node.label,
          domain: 'COMPANY',
          department: node.department || 'Unknown',
          privileged: node.privileged || false,
          enabled: node.enabled !== false,
          groups: node.privileged ? ['Domain Admins'] : ['Domain Users'],
          normalLoginHours: { start: 8, end: 17 }
        })),
      ipIntelligence: sampleData.nodes
        .filter((node: any) => node.type === 'ip')
        .map((node: any) => ({
          ip: node.label,
          country: node.country || 'Unknown',
          city: node.city || 'Unknown',
          isVpn: false,
          isTor: node.tor || false,
          isMalicious: node.riskScore > 90,
          riskScore: node.riskScore || 0
        }))
    }

    return { events, context }
  }, [])

  /**
   * Get anomaly summary statistics
   */
  const getAnomalyStats = useCallback((anomalies: Anomaly[]) => {
    const bySeverity = anomalies.reduce((acc, anomaly) => {
      acc[anomaly.severity] = (acc[anomaly.severity] || 0) + 1
      return acc
    }, {} as Record<string, number>)

    const byCategory = anomalies.reduce((acc, anomaly) => {
      acc[anomaly.category] = (acc[anomaly.category] || 0) + 1
      return acc
    }, {} as Record<string, number>)

    const byRule = anomalies.reduce((acc, anomaly) => {
      acc[anomaly.ruleName] = (acc[anomaly.ruleName] || 0) + 1
      return acc
    }, {} as Record<string, number>)

    const avgConfidence = anomalies.length > 0 
      ? anomalies.reduce((sum, a) => sum + a.confidence, 0) / anomalies.length 
      : 0

    return {
      total: anomalies.length,
      bySeverity,
      byCategory,
      byRule,
      avgConfidence: Math.round(avgConfidence)
    }
  }, [])

  return {
    // State
    isAnalyzing,
    lastResult,
    error,
    userRuleConfigs,

    // Analytics functions
    analyzeEvents,
    analyzeByCategory,
    testRule,

    // Rule management
    getRules,
    getEnabledRules,
    toggleRule,
    updateRuleConfig,
    loadUserRuleConfigs,

    // User configuration management
    saveUserRuleConfig: RuleConfigService.saveUserRuleConfig,
    deleteUserRuleConfig: RuleConfigService.deleteUserRuleConfig,
    getUserRuleConfig: RuleConfigService.getUserRuleConfig,

    // Utilities
    getStatistics,
    processSampleData,
    getAnomalyStats,

    // Direct engine access (for advanced usage)
    engine
  }
}
