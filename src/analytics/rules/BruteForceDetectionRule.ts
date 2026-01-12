import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext } from '../types'

export class BruteForceDetectionRule extends BaseRule {
  constructor() {
    super({
      id: 'brute_force_detection',
      name: 'Brute Force Attack Detection',
      description: 'Detects potential brute force attacks based on multiple failed login attempts',
      category: 'authentication',
      severity: 'high',
      timeWindow: 30, // 30 minutes
      thresholds: {
        failedAttempts: 5,
        uniqueSourceIps: 1, // From same IP
        timeWindowMinutes: 10 // Within 10 minutes
      },
      version: '1.2.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects potential brute force attacks based on multiple failed login attempts from the same source. Monitors authentication patterns to identify both single-user and multi-user brute force campaigns.',
        detectionLogic: 'Analyzes authentication events within time windows, grouping failed login attempts by user and source IP. Calculates attempt frequency and identifies distributed attacks across multiple IPs. Detects both single-user brute force (same user, multiple attempts) and multi-user brute force (same IP, multiple users).',
        falsePositives: 'Legitimate password recovery attempts, misconfigured applications, shared accounts, forgotten passwords, or users with multiple legitimate login attempts from different locations.',
        mitigation: [
          'Implement account lockout policies after failed attempts',
          'Enable multi-factor authentication for all accounts',
          'Configure progressive delays between failed login attempts',
          'Implement CAPTCHA for repeated failures from same IP',
          'Monitor for password spraying campaigns',
          'Set up anomaly detection for authentication patterns',
          'Use rate limiting on authentication endpoints'
        ],
        windowsEvents: ['4625 (Failed Logon)', '4624 (Successful Logon)', '4771 (Kerberos Pre-auth Failed)', '4776 (NTLM Authentication)'],
        exampleQuery: `index=windows EventCode=4625 | bucket span=5m _time | stats count by TargetUserName, IpAddress | where count > 5`,
        recommendedThresholds: {
          failedAttempts: 5,
          timeWindowMinutes: 10,
          uniqueSourceIps: 1
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    const recentEvents = this.filterByTimeWindow(events)
    const failedLogins = recentEvents.filter(event => event.status === 'Failed')

    // Group failed logins by target user
    const failedByUser = this.groupBy(failedLogins, event => 
      `${event.userName}@${event.domainName || 'unknown'}`
    )

    // Analyze each user's failed login attempts
    Object.entries(failedByUser).forEach(([userKey, userFailedLogins]) => {
      if (userFailedLogins.length >= this.thresholds.failedAttempts) {
        
        // Check if attacks came from multiple IPs (distributed attack)
        const sourceIps = new Set(userFailedLogins.map(event => event.sourceIp).filter(Boolean))
        const isDistributed = sourceIps.size > 1

        // Check if there was a successful login after failed attempts
        const userName = userFailedLogins[0].userName
        const successfulAfterFailed = recentEvents.some(event => {
          const eventTimestamp = event.timestamp instanceof Date
            ? event.timestamp.getTime()
            : new Date(event.timestamp).getTime()

          const latestFailedTimestamp = Math.max(...userFailedLogins.map(e =>
            e.timestamp instanceof Date
              ? e.timestamp.getTime()
              : new Date(e.timestamp).getTime()
          ))

          return event.userName === userName &&
                 event.status === 'Success' &&
                 eventTimestamp > latestFailedTimestamp
        })

        // Calculate confidence based on various factors
        let confidence = 70
        if (userFailedLogins.length > 10) confidence += 15
        if (isDistributed) confidence += 10
        if (successfulAfterFailed) confidence += 20
        if (userFailedLogins.length > 20) confidence += 15

        // Check for rapid-fire attempts (high frequency)
        const timeSpan = Math.max(...userFailedLogins.map(e => e.timestamp.getTime())) - 
                        Math.min(...userFailedLogins.map(e => e.timestamp.getTime()))
        const attemptFrequency = userFailedLogins.length / (timeSpan / (1000 * 60)) // attempts per minute
        
        if (attemptFrequency > 2) confidence += 10 // More than 2 attempts per minute

        const anomaly = this.createAnomaly(
          isDistributed ? 'Distributed Brute Force Attack Detected' : 'Brute Force Attack Detected',
          `${userFailedLogins.length} failed login attempts detected for user ${userName}${
            isDistributed ? ` from ${sourceIps.size} different IP addresses` : ''
          }${successfulAfterFailed ? '. Successful login detected after failed attempts.' : ''}`,
          {
            userName,
            domain: userFailedLogins[0].domainName,
            failedAttempts: userFailedLogins.length,
            sourceIps: Array.from(sourceIps),
            isDistributed,
            successfulAfterFailed,
            attemptFrequency: Math.round(attemptFrequency * 10) / 10,
            timeSpanMinutes: Math.round(timeSpan / (1000 * 60) * 10) / 10,
            computers: Array.from(new Set(userFailedLogins.map(e => e.computerName).filter(Boolean))),
            firstAttempt: new Date(Math.min(...userFailedLogins.map(e => e.timestamp.getTime()))),
            lastAttempt: new Date(Math.max(...userFailedLogins.map(e => e.timestamp.getTime()))),
            failureReasons: Array.from(new Set(userFailedLogins.map(e => e.failureReason).filter(Boolean)))
          },
          confidence,
          {
            ruleVersion: this.version,
            thresholds: this.thresholds,
            analysisTimestamp: new Date()
          }
        )

        anomalies.push(anomaly)
      }
    })

    // Also check for IP-based brute force (same IP attacking multiple users)
    const failedByIp = this.groupBy(failedLogins, event => event.sourceIp || 'unknown')
    
    Object.entries(failedByIp).forEach(([sourceIp, ipFailedLogins]) => {
      if (sourceIp !== 'unknown' && ipFailedLogins.length >= this.thresholds.failedAttempts) {
        const targetUsers = new Set(ipFailedLogins.map(event => event.userName).filter(Boolean))
        
        if (targetUsers.size > 1) { // Attacking multiple users
          let confidence = 75
          if (targetUsers.size > 3) confidence += 15
          if (ipFailedLogins.length > 15) confidence += 10

          const anomaly = this.createAnomaly(
            'Multi-User Brute Force Attack from Single IP',
            `${ipFailedLogins.length} failed login attempts from IP ${sourceIp} targeting ${targetUsers.size} different users`,
            {
              sourceIp,
              failedAttempts: ipFailedLogins.length,
              targetUsers: Array.from(targetUsers),
              computers: Array.from(new Set(ipFailedLogins.map(e => e.computerName).filter(Boolean))),
              firstAttempt: new Date(Math.min(...ipFailedLogins.map(e => e.timestamp.getTime()))),
              lastAttempt: new Date(Math.max(...ipFailedLogins.map(e => e.timestamp.getTime())))
            },
            confidence,
            {
              ruleVersion: this.version,
              attackType: 'multi_user_brute_force'
            }
          )

          anomalies.push(anomaly)
        }
      }
    })

    return anomalies
  }
}
