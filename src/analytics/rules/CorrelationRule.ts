import { AnalyticsRule, AuthEvent, AnalyticsContext, Anomaly } from '../types'

export abstract class CorrelationRule implements AnalyticsRule {
  id: string
  name: string
  description: string
  detailedDescription?: {
    overview: string
    detectionLogic: string
    falsePositives: string
    mitigation: string[]
    windowsEvents: string[]
    exampleQuery: string
    recommendedThresholds: Record<string, any>
  }
  category: 'correlation'
  severity: 'low' | 'medium' | 'high' | 'critical'
  enabled: boolean
  timeWindow: number
  thresholds: Record<string, number>
  version: string
  author: string
  created: Date
  updated: Date

  constructor(
    id: string,
    name: string,
    description: string,
    severity: 'low' | 'medium' | 'high' | 'critical' = 'high',
    timeWindow: number = 60, // minutes
    thresholds: Record<string, number> = {},
    detailedDescription?: {
      overview: string
      detectionLogic: string
      falsePositives: string
      mitigation: string[]
      windowsEvents: string[]
      exampleQuery: string
      recommendedThresholds: Record<string, any>
    }
  ) {
    this.id = id
    this.name = name
    this.description = description
    this.detailedDescription = detailedDescription || {
      overview: 'Base correlation rule framework that analyzes relationships between multiple security events to detect complex attack patterns and sophisticated threat behaviors. Provides temporal correlation capabilities for identifying multi-stage attacks and advanced persistent threats.',
      detectionLogic: 'Analyzes event sequences within configurable time windows, correlates related security events across different sources, and applies statistical analysis to identify patterns that indicate coordinated attacks or sophisticated threat actor behavior.',
      falsePositives: 'Legitimate administrative activities that occur in sequence, automated system maintenance operations, legitimate user behavior that appears suspicious when viewed in isolation, or normal business processes that involve multiple security events in sequence.',
      mitigation: [
        'Implement multi-factor authentication for all privileged accounts',
        'Enable comprehensive security event logging and monitoring',
        'Establish baseline user and system behavior patterns',
        'Implement automated response capabilities for detected threats',
        'Conduct regular security awareness training for administrators',
        'Maintain up-to-date threat intelligence and correlation rules',
        'Implement network segmentation and zero trust principles',
        'Regular security assessments and penetration testing',
        'Enable advanced threat detection and response capabilities',
        'Implement security information and event management (SIEM) integration'
      ],
      windowsEvents: ['All authentication events (4624, 4625, 4672, etc.)', 'All authorization events (4672, 4673, 4674)', 'All account management events (4720-4739)', 'All privilege use events (4672, 4673)', 'All object access events (4656, 4663)', 'All system events (4616, 4621)', 'All policy change events (4715-4739)', 'All audit events (4902-4912)'],
      exampleQuery: `index=windows EventCode=* | stats count by TargetUserName, Computer | where count > 5`,
      recommendedThresholds: {
        minAlerts: 3,
        timeWindowMinutes: 30,
        confidenceThreshold: 0.7
      }
    }
    this.category = 'correlation'
    this.severity = severity
    this.enabled = true
    this.timeWindow = timeWindow
    this.thresholds = {
      minAlerts: 3,
      timeWindowMinutes: 30,
      confidenceThreshold: 0.7,
      ...thresholds
    }
    this.version = '1.0.0'
    this.author = 'ADTrapper'
    this.created = new Date()
    this.updated = new Date()
  }

  /**
   * Validate rule configuration
   */
  validate(): { valid: boolean; errors: string[] } {
    const errors: string[] = []

    if (!this.id || this.id.trim().length === 0) {
      errors.push('Rule ID is required')
    }

    if (!this.name || this.name.trim().length === 0) {
      errors.push('Rule name is required')
    }

    if (!this.description || this.description.trim().length === 0) {
      errors.push('Rule description is required')
    }

    if (this.timeWindow <= 0) {
      errors.push('Time window must be positive')
    }

    return {
      valid: errors.length === 0,
      errors
    }
  }

  /**
   * Get rule metadata
   */
  getMetadata(): any {
    return {
      id: this.id,
      name: this.name,
      description: this.description,
      category: this.category,
      severity: this.severity,
      enabled: this.enabled,
      timeWindow: this.timeWindow,
      thresholds: this.thresholds,
      version: this.version,
      author: this.author,
      created: this.created,
      updated: this.updated
    }
  }

  /**
   * Main analysis function - implemented by subclasses
   */
  abstract analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]>

  /**
   * Helper function to group alerts by entity combinations
   */
  protected groupAlertsByEntities(alerts: Anomaly[]): Map<string, Anomaly[]> {
    const entityGroups = new Map<string, Anomaly[]>()

    alerts.forEach(alert => {
      if (!alert.affectedEntities || alert.affectedEntities.length === 0) {
        return
      }

      // Create combinations of entities
      const combinations = this.generateEntityCombinations(alert.affectedEntities)

      combinations.forEach(combination => {
        const key = this.getCombinationKey(combination)
        if (!entityGroups.has(key)) {
          entityGroups.set(key, [])
        }
        entityGroups.get(key)!.push(alert)
      })
    })

    return entityGroups
  }

  /**
   * Generate meaningful entity combinations
   */
  private generateEntityCombinations(entities: Array<{ type: 'user' | 'computer' | 'ip'; id: string; name: string }>): Array<Array<{ type: string; id: string; name: string }>> {
    const combinations: Array<Array<{ type: string; id: string; name: string }>> = []

    // Single entities
    entities.forEach(entity => {
      combinations.push([entity])
    })

    // User + Computer combinations (most common correlation)
    const users = entities.filter(e => e.type === 'user')
    const computers = entities.filter(e => e.type === 'computer')

    users.forEach(user => {
      computers.forEach(computer => {
        combinations.push([user, computer])
      })
    })

    // User + IP combinations
    const ips = entities.filter(e => e.type === 'ip')
    users.forEach(user => {
      ips.forEach(ip => {
        combinations.push([user, ip])
      })
    })

    // Computer + IP combinations
    computers.forEach(computer => {
      ips.forEach(ip => {
        combinations.push([computer, ip])
      })
    })

    return combinations
  }

  /**
   * Create a unique key for entity combination
   */
  private getCombinationKey(combination: Array<{ type: string; id: string; name: string }>): string {
    return combination
      .sort((a, b) => a.type.localeCompare(b.type) || a.id.localeCompare(b.id))
      .map(entity => `${entity.type}:${entity.id}`)
      .join('|')
  }

  /**
   * Calculate correlation score based on various factors
   */
  protected calculateCorrelationScore(
    alerts: Anomaly[],
    timeWindowMinutes: number,
    factors: {
      severityWeight?: number
      timeClosenessWeight?: number
      alertDiversityWeight?: number
      entityOverlapWeight?: number
    } = {}
  ): number {
    const {
      severityWeight = 0.3,
      timeClosenessWeight = 0.3,
      alertDiversityWeight = 0.2,
      entityOverlapWeight = 0.2
    } = factors

    if (alerts.length === 0) return 0

    // Severity factor
    const severityScore = alerts.reduce((sum, alert) => {
      const severityValue = { low: 1, medium: 2, high: 3, critical: 4, info: 0.5 }[alert.severity] || 1
      return sum + severityValue
    }, 0) / alerts.length

    // Time closeness factor
    const timestamps = alerts.map(a => new Date(a.detectedAt).getTime())
    const timeSpan = Math.max(...timestamps) - Math.min(...timestamps)
    const timeCloseness = Math.max(0, 1 - (timeSpan / (timeWindowMinutes * 60 * 1000)))

    // Alert diversity factor
    const uniqueRules = new Set(alerts.map(a => a.ruleId)).size
    const alertDiversity = Math.min(1, uniqueRules / alerts.length)

    // Entity overlap factor
    const allEntities = alerts.flatMap(a => a.affectedEntities || [])
    const uniqueEntities = new Set(allEntities.map(e => `${e.type}:${e.id}`))
    const entityOverlap = uniqueEntities.size > 0 ? (allEntities.length / uniqueEntities.size) / alerts.length : 0

    // Calculate final score
    const score = (
      severityScore * severityWeight +
      timeCloseness * timeClosenessWeight +
      alertDiversity * alertDiversityWeight +
      entityOverlap * entityOverlapWeight
    ) / 4

    return Math.min(1, Math.max(0, score))
  }

  /**
   * Create correlation anomaly
   */
  protected createCorrelationAnomaly(
    title: string,
    description: string,
    alerts: Anomaly[],
    confidence: number,
    affectedEntities: Array<{ type: 'user' | 'computer' | 'ip'; id: string; name: string }>,
    evidence: Record<string, any>,
    recommendations: string[] = [],
    eventTimestamp?: Date
  ): Anomaly {
    const latestTimestamp = alerts.length > 0
      ? new Date(Math.max(...alerts.map(a => new Date(a.detectedAt).getTime())))
      : eventTimestamp || new Date()

    const earliestTimestamp = alerts.length > 0
      ? new Date(Math.min(...alerts.map(a => new Date(a.detectedAt).getTime())))
      : latestTimestamp

    // Use the event timestamp if available, otherwise use the latest alert timestamp
    const anomalyTimestamp = eventTimestamp || latestTimestamp

    return {
      id: `correlation-${this.id}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      ruleId: this.id,
      ruleName: this.name,
      severity: this.severity,
      title,
      description,
      category: 'correlation',
      confidence,
      evidence,
      affectedEntities,
      timeWindow: {
        start: earliestTimestamp,
        end: latestTimestamp
      },
      metadata: {
        correlatedAlerts: alerts.length > 0 ? alerts.map(a => ({
          id: a.id,
          title: a.title,
          severity: a.severity,
          timestamp: a.timestamp,
          detectedAt: a.detectedAt
        })) : [],
        alertCount: alerts.length,
        uniqueRules: new Set(alerts.map(a => a.ruleId)).size,
        timeSpan: latestTimestamp.getTime() - earliestTimestamp.getTime(),
        timeSpanFormatted: this.formatTimeSpan(latestTimestamp.getTime() - earliestTimestamp.getTime())
      },
      timestamp: anomalyTimestamp,
      detectedAt: new Date(),
      recommendations
    }
  }

  /**
   * Format time span for display
   */
  private formatTimeSpan(milliseconds: number): string {
    const seconds = Math.floor(milliseconds / 1000)
    const minutes = Math.floor(seconds / 60)
    const hours = Math.floor(minutes / 60)
    const days = Math.floor(hours / 24)

    if (days > 0) return `${days} day${days > 1 ? 's' : ''}`
    if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''}`
    if (minutes > 0) return `${minutes} minute${minutes > 1 ? 's' : ''}`
    return `${seconds} second${seconds > 1 ? 's' : ''}`
  }
}
