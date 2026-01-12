import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext } from '../types'

export class PasswordSprayPatternRule extends BaseRule {
  constructor() {
    super({
      id: 'password_spray_pattern_detection',
      name: 'Password Spray Pattern Detection',
      description: 'Detects password spraying using AD user attributes and temporal patterns',
      category: 'authentication',
      severity: 'critical',
      timeWindow: 10, // 10 minutes for pattern detection
      thresholds: {
        minSimultaneousFailures: 5, // Minimum users with failures in same time window
        timeWindowSeconds: 300, // 5 minutes for simultaneous detection
        badPasswordCountThreshold: 2, // Minimum bad password attempts per user
        recentFailureThreshold: 120 // Seconds - failures within this time are "recent"
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects password spraying attacks using multiple analysis methods including AD user attributes, temporal patterns, and IP-based analysis. Password spraying is a stealthy attack technique that attempts a single password against many accounts to avoid account lockouts.',
        detectionLogic: 'Combines three detection methods: (1) AD attribute analysis examining badPasswordCount and lastBadPasswordAttempt across users, (2) Temporal pattern analysis identifying simultaneous failures across multiple users, (3) IP-based analysis tracking authentication attempts from single sources targeting multiple accounts.',
        falsePositives: 'Legitimate password synchronization issues, shared account usage, password policy enforcement, or users with similar password change patterns. May also trigger on legitimate bulk authentication scenarios.',
        mitigation: [
          'Implement account lockout policies with exponential backoff',
          'Enable multi-factor authentication for all accounts',
          'Monitor for low-and-slow attack patterns',
          'Implement behavioral analytics for authentication',
          'Set up password spray detection alerts',
          'Use account lockout thresholds that exceed typical spraying patterns',
          'Implement geolocation-based authentication policies',
          'Regular password audits and complexity enforcement'
        ],
        windowsEvents: ['4625 (Failed Logon)', '4624 (Successful Logon)', '4771 (Kerberos Pre-auth Failed)', '4776 (NTLM Authentication)', '4740 (User Account Locked Out)'],
        exampleQuery: `index=windows EventCode=4625 | bucket span=5m _time | stats dc(TargetUserName) as unique_users by _time, IpAddress | where unique_users > 5`,
        recommendedThresholds: {
          minSimultaneousFailures: 5,
          timeWindowSeconds: 300,
          badPasswordCountThreshold: 2,
          recentFailureThreshold: 120
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Method 1: Analyze AD user attributes for password spraying patterns
    const adAttributeAnomalies = this.analyzeADAttributes(context)
    anomalies.push(...adAttributeAnomalies)

    // Method 2: Analyze temporal patterns in authentication events
    const temporalAnomalies = this.analyzeTemporalPatterns(events, context)
    anomalies.push(...temporalAnomalies)

    // Method 3: Analyze IP-based patterns across multiple accounts
    const ipPatternAnomalies = this.analyzeIPPatterns(events)
    anomalies.push(...ipPatternAnomalies)

    return anomalies
  }

  private analyzeADAttributes(context: AnalyticsContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    if (!context.userProfiles) return anomalies

    // Group users by their last bad password attempt time
    const usersByFailureTime: Record<string, any[]> = {}

    context.userProfiles.forEach(user => {
      if (user.lastBadPasswordAttempt && user.badPasswordCount && user.badPasswordCount >= this.thresholds.badPasswordCountThreshold) {
        const failureTime = new Date(user.lastBadPasswordAttempt).getTime()
        const timeKey = Math.floor(failureTime / (this.thresholds.timeWindowSeconds * 1000))

        if (!usersByFailureTime[timeKey]) {
          usersByFailureTime[timeKey] = []
        }
        usersByFailureTime[timeKey].push(user)
      }
    })

    // Find time windows with many simultaneous failures
    Object.entries(usersByFailureTime).forEach(([timeKey, users]) => {
      if (users.length >= this.thresholds.minSimultaneousFailures) {
        const timeWindow = new Date(parseInt(timeKey) * this.thresholds.timeWindowSeconds * 1000)
        const recentFailures = users.filter(user =>
          user.lastBadPasswordAttempt &&
          (new Date().getTime() - new Date(user.lastBadPasswordAttempt).getTime()) / 1000 <= this.thresholds.recentFailureThreshold
        )

        if (recentFailures.length >= this.thresholds.minSimultaneousFailures) {
          const confidence = Math.min(95, 70 + (recentFailures.length * 5))

          const anomaly = this.createAnomaly(
            'Simultaneous Account Lockout Pattern',
            `${recentFailures.length} users experienced authentication failures within ${this.thresholds.timeWindowSeconds} seconds of each other`,
            {
              affectedUsers: recentFailures.map(user => ({
                userName: user.userName,
                domain: user.domain,
                badPasswordCount: user.badPasswordCount,
                lastBadPasswordAttempt: user.lastBadPasswordAttempt,
                department: user.department
              })),
              totalAffectedUsers: recentFailures.length,
              timeWindow: timeWindow.toISOString(),
              detectionMethod: 'ad_attributes',
              patternType: 'simultaneous_failures'
            },
            confidence,
            {
              attackType: 'password_spraying',
              detectionMethod: 'ad_user_attributes',
              riskFactors: [
                'Multiple users with authentication failures in short time window',
                'Users have elevated bad password counts',
                'Failures occurred recently'
              ]
            }
          )

          anomalies.push(anomaly)
        }
      }
    })

    return anomalies
  }

  private analyzeTemporalPatterns(events: AuthEvent[], context: AnalyticsContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    // Get failed authentication events
    const failedEvents = events.filter(event =>
      event.status === 'Failed' &&
      (event.eventId === '4625' || event.eventId === '4771') &&
      event.userName &&
      event.userName !== 'ANONYMOUS LOGON'
    )

    if (failedEvents.length < this.thresholds.minSimultaneousFailures) return anomalies

    // Group by time windows
    const timeWindows: Record<string, AuthEvent[]> = {}

    failedEvents.forEach(event => {
      // Handle both Date objects and string timestamps
      const timestamp = event.timestamp instanceof Date
        ? event.timestamp.getTime()
        : new Date(event.timestamp).getTime()

      const windowKey = Math.floor(timestamp / (this.thresholds.timeWindowSeconds * 1000))

      if (!timeWindows[windowKey]) {
        timeWindows[windowKey] = []
      }
      timeWindows[windowKey].push(event)
    })

    // Analyze each time window
    Object.entries(timeWindows).forEach(([windowKey, windowEvents]) => {
      const uniqueUsers = new Set(windowEvents.map(e => e.userName).filter(u => u))
      const uniqueIPs = new Set(windowEvents.map(e => e.sourceIp).filter(ip => ip))

      if (uniqueUsers.size >= this.thresholds.minSimultaneousFailures) {
        // Calculate failure distribution
        const userFailureCounts = Array.from(uniqueUsers).map(userName => ({
          userName,
          failureCount: windowEvents.filter(e => e.userName === userName).length
        }))

        // Check for even distribution (typical of password spraying)
        const avgFailures = userFailureCounts.reduce((sum, ufc) => sum + ufc.failureCount, 0) / userFailureCounts.length
        const variance = userFailureCounts.reduce((sum, ufc) => sum + Math.pow(ufc.failureCount - avgFailures, 2), 0) / userFailureCounts.length
        const stdDev = Math.sqrt(variance)
        const coefficientOfVariation = stdDev / avgFailures

        // Low coefficient of variation indicates even distribution (password spraying pattern)
        if (coefficientOfVariation < 0.5 && uniqueIPs.size <= 3) {
          const confidence = Math.min(90, 60 + (uniqueUsers.size * 3))

          const anomaly = this.createAnomaly(
            'Password Spraying Temporal Pattern',
            `Detected ${uniqueUsers.size} users with authentication failures in a ${this.thresholds.timeWindowSeconds}-second window from ${uniqueIPs.size} source(s)`,
            {
              affectedUsers: userFailureCounts,
              totalFailures: windowEvents.length,
              uniqueUsers: uniqueUsers.size,
              uniqueIPs: Array.from(uniqueIPs),
              sourceIPs: Array.from(uniqueIPs),
              timeWindowStart: new Date(parseInt(windowKey) * this.thresholds.timeWindowSeconds * 1000).toISOString(),
              coefficientOfVariation: Math.round(coefficientOfVariation * 100) / 100,
              statisticalAnalysis: {
                averageFailures: Math.round(avgFailures * 10) / 10,
                standardDeviation: Math.round(stdDev * 10) / 10,
                evenDistribution: coefficientOfVariation < 0.5
              },
              detectionMethod: 'temporal_pattern'
            },
            confidence,
            {
              attackType: 'password_spraying',
              detectionMethod: 'temporal_analysis',
              riskFactors: [
                'Even distribution of failures across multiple users',
                'Failures concentrated in short time window',
                'Limited number of source IPs'
              ]
            }
          )

          anomalies.push(anomaly)
        }
      }
    })

    return anomalies
  }

  private analyzeIPPatterns(events: AuthEvent[]): Anomaly[] {
    const anomalies: Anomaly[] = []

    // Group failed events by source IP
    const ipGroups = this.groupBy(events.filter(e => e.status === 'Failed'), e => e.sourceIp || 'unknown')

    Object.entries(ipGroups).forEach(([sourceIP, ipEvents]) => {
      if (sourceIP === 'unknown' || ipEvents.length < this.thresholds.minSimultaneousFailures) return

      const uniqueUsers = new Set(ipEvents.map(e => e.userName).filter(u => u))
      const eventTypes = new Set(ipEvents.map(e => e.eventId))

      // Check for password spraying characteristics
      if (uniqueUsers.size >= this.thresholds.minSimultaneousFailures) {
        const timeSpan = this.calculateTimeSpan(ipEvents)
        const eventsPerMinute = ipEvents.length / Math.max(1, timeSpan / (1000 * 60))

        // High events per minute with many unique users suggests spraying
        if (eventsPerMinute > 10 && uniqueUsers.size > this.thresholds.minSimultaneousFailures) {
          const confidence = Math.min(85, 50 + (uniqueUsers.size * 2) + Math.floor(eventsPerMinute))

          const anomaly = this.createAnomaly(
            'Password Spraying by Source IP',
            `Source ${sourceIP} attempted authentication against ${uniqueUsers.size} users (${Math.round(eventsPerMinute)} attempts/minute)`,
            {
              sourceIP,
              targetUsers: Array.from(uniqueUsers),
              totalAttempts: ipEvents.length,
              eventsPerMinute: Math.round(eventsPerMinute * 10) / 10,
              uniqueUsers: uniqueUsers.size,
              eventTypes: Array.from(eventTypes),
              timeSpanMinutes: Math.round(timeSpan / (1000 * 60) * 10) / 10,
              userBreakdown: Array.from(uniqueUsers).map(user => ({
                userName: user,
                attempts: ipEvents.filter(e => e.userName === user).length
              })),
              detectionMethod: 'ip_analysis'
            },
            confidence,
            {
              attackType: 'password_spraying',
              detectionMethod: 'source_ip_analysis',
              riskFactors: [
                'High authentication attempt rate',
                'Multiple unique users targeted',
                'Concentrated from single source IP'
              ]
            }
          )

          anomalies.push(anomaly)
        }
      }
    })

    return anomalies
  }

  private calculateTimeSpan(events: AuthEvent[]): number {
    if (events.length === 0) return 0

    const timestamps = events.map(e =>
      typeof e.timestamp === 'string' ? new Date(e.timestamp).getTime() : e.timestamp.getTime()
    ).sort()
    return timestamps[timestamps.length - 1] - timestamps[0]
  }
}
