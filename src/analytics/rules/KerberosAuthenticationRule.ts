import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext } from '../types'

export class KerberosAuthenticationRule extends BaseRule {
  constructor() {
    super({
      id: 'kerberos_authentication_failures',
      name: 'Kerberos Authentication Failures',
      description: 'Detects unusual patterns of Kerberos authentication failures',
      category: 'authentication',
      severity: 'high',
      timeWindow: 5, // 5 minutes to match Splunk query
      thresholds: {
        uniqueAccountsThreshold: 30,
        statisticalThreshold: 10, // Minimum count for statistical analysis
        outlierMultiplier: 3 // Standard deviation multiplier for outliers
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects unusual patterns of Kerberos authentication failures that may indicate account enumeration, password spraying, or Kerberos-based attacks. Monitors for statistical outliers and patterns that deviate from normal authentication behavior.',
        detectionLogic: 'Analyzes Kerberos pre-authentication failures (event 4771) grouped by source IP and time windows. Uses statistical analysis to identify outliers - users with significantly higher failure rates than the average. Detects patterns indicative of account enumeration or systematic password testing.',
        falsePositives: 'Clock skew issues between domain controllers, expired user tickets, network connectivity problems, or legitimate bulk authentication attempts. May also trigger during password policy enforcement or account maintenance activities.',
        mitigation: [
          'Ensure proper time synchronization across domain',
          'Monitor for Kerberos ticket attacks (Golden/Silver tickets)',
          'Implement Kerberos armoring to prevent relay attacks',
          'Enable account lockout policies for Kerberos failures',
          'Regular password policy enforcement and auditing',
          'Implement network segmentation to limit attack surface',
          'Use Kerberos FAST (Flexible Authentication Secure Tunneling)',
          'Monitor for unusual Kerberos service ticket requests'
        ],
        windowsEvents: ['4771 (Kerberos Pre-auth Failed)', '4768 (Kerberos TGT Requested)', '4772 (Kerberos TGT Failed)', '4769 (Kerberos Service Ticket Requested)', '4770 (Kerberos Service Ticket Renewed)'],
        exampleQuery: `index=windows EventCode=4771 TargetUserName!="$*" Status=0x18 | bucket span=5m _time | stats dc(TargetUserName) AS unique_accounts by _time, IpAddress | where unique_accounts > 10`,
        recommendedThresholds: {
          uniqueAccountsThreshold: 30,
          statisticalThreshold: 10,
          outlierMultiplier: 3
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Filter Kerberos authentication failures (EventCode 4771)
    const kerberosFailures = events.filter(event =>
      event.eventId === '4771' &&
      event.status === 'Failed' &&
      event.userName &&
      event.userName !== '*' &&
      event.sourceIp
    )

    if (kerberosFailures.length === 0) return anomalies

    // Group by source IP and time windows
    const sourceGroups = this.groupBySourceAndTime(kerberosFailures)

    Object.entries(sourceGroups).forEach(([sourceIP, sourceEvents]) => {
      const uniqueUsers = new Set(sourceEvents.map(e => e.userName).filter(u => u))

      if (uniqueUsers.size >= this.thresholds.uniqueAccountsThreshold) {
        // Statistical analysis for outliers
        const userCounts = Array.from(uniqueUsers).map(user => ({
          user,
          count: sourceEvents.filter(e => e.userName === user).length
        }))

        // Calculate statistics for this IP
        const counts = userCounts.map(uc => uc.count)
        const avg = counts.reduce((sum, count) => sum + count, 0) / counts.length
        const variance = counts.reduce((sum, count) => sum + Math.pow(count - avg, 2), 0) / counts.length
        const stdDev = Math.sqrt(variance)
        const upperBound = avg + (stdDev * this.thresholds.outlierMultiplier)

        // Find outlier users (unusually high failure counts)
        const outlierUsers = userCounts.filter(uc =>
          uc.count >= this.thresholds.statisticalThreshold &&
          uc.count >= upperBound
        )

        if (outlierUsers.length > 0) {
          const confidence = Math.min(95, 60 + (outlierUsers.length * 10))

          const anomaly = this.createAnomaly(
            'Kerberos Authentication Attack Pattern',
            `${uniqueUsers.size} unique users failed Kerberos authentication from ${sourceIP}, with ${outlierUsers.length} users showing outlier behavior`,
            {
              sourceIP,
              uniqueUsers: Array.from(uniqueUsers),
              totalFailures: sourceEvents.length,
              outlierUsers: outlierUsers.map(ou => ({
                user: ou.user,
                failureCount: ou.count,
                percentage: Math.round((ou.count / sourceEvents.length) * 100)
              })),
              statisticalAnalysis: {
                averageFailures: Math.round(avg * 10) / 10,
                standardDeviation: Math.round(stdDev * 10) / 10,
                upperBound: Math.round(upperBound * 10) / 10
              },
              failureReasons: Array.from(new Set(sourceEvents.map(e => e.failureReason).filter(r => r))),
              computers: Array.from(new Set(sourceEvents.map(e => e.computerName).filter(c => c)))
            },
            confidence,
            {
              attackType: 'kerberos_enumeration',
              detectionMethod: 'statistical_outlier'
            }
          )

          anomalies.push(anomaly)
        }
      }
    })

    return anomalies
  }

  private groupBySourceAndTime(events: AuthEvent[]): Record<string, AuthEvent[]> {
    const groups: Record<string, AuthEvent[]> = {}

    events.forEach(event => {
      if (!event.sourceIp) return

      // Handle both Date objects and string timestamps
      const timestamp = event.timestamp instanceof Date
        ? event.timestamp.getTime()
        : new Date(event.timestamp).getTime()

      // Create 5-minute time windows
      const windowStart = Math.floor(timestamp / (5 * 60 * 1000)) * (5 * 60 * 1000)
      const timeWindow = new Date(windowStart).toISOString()

      const key = `${event.sourceIp}|${timeWindow}`

      if (!groups[key]) {
        groups[key] = []
      }
      groups[key].push(event)
    })

    return groups
  }
}
