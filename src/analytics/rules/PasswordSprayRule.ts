import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext } from '../types'

export class PasswordSprayRule extends BaseRule {
  constructor() {
    super({
      id: 'password_spray_detection',
      name: 'Password Spray Attack Detection',
      description: 'Detects password spray attacks where one password is tried against multiple accounts',
      category: 'authentication',
      severity: 'critical',
      timeWindow: 30, // 30 minutes window for spray detection
      thresholds: {
        minTargetUsers: 10,
        successToFailureRatio: 0.25, // Less than 25% success rate
        minTotalAttempts: 20
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects password spray attacks where attackers attempt the same password against multiple accounts from a single source. This stealthy technique avoids account lockouts while potentially compromising multiple user accounts.',
        detectionLogic: 'Analyzes authentication events from each source IP, calculating success-to-failure ratios and unique target counts. Identifies patterns where one source attempts authentication against many users with consistently low success rates, indicating systematic password testing.',
        falsePositives: 'Legitimate administrative tools accessing multiple accounts, password synchronization utilities, shared workstation scenarios, or users with similar passwords. May also trigger during legitimate bulk authentication operations.',
        mitigation: [
          'Implement multi-factor authentication for all accounts',
          'Configure account lockout policies that account for spray patterns',
          'Monitor for low-and-slow authentication patterns',
          'Implement behavioral analytics and anomaly detection',
          'Use CAPTCHA for repeated authentication attempts',
          'Enable rate limiting on authentication endpoints',
          'Regular password audits and complexity enforcement',
          'Implement geolocation-based authentication restrictions'
        ],
        windowsEvents: ['4625 (Failed Logon)', '4624 (Successful Logon)', '4771 (Kerberos Pre-auth Failed)', '4776 (NTLM Authentication)', '4648 (Explicit Credential Logon)'],
        exampleQuery: `index=windows EventCode=4625 OR EventCode=4624 | stats count by IpAddress, TargetUserName | stats sum(count) as total_attempts, dc(TargetUserName) as unique_users by IpAddress | where total_attempts > 20 AND unique_users > 10`,
        recommendedThresholds: {
          minTargetUsers: 10,
          successToFailureRatio: 0.25,
          minTotalAttempts: 20
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Get all authentication events in the time window
    const authEvents = events.filter(event =>
      (event.eventId === '4624' || event.eventId === '4625') &&
      event.userName &&
      event.userName !== 'ANONYMOUS LOGON' &&
      event.userName !== '*'
    )

    if (authEvents.length < this.thresholds.minTotalAttempts) return anomalies

    // Group by source IP
    const sourceGroups = this.groupBy(authEvents, event => event.sourceIp || 'unknown')

    Object.entries(sourceGroups).forEach(([sourceIP, sourceEvents]) => {
      if (sourceIP === 'unknown') return

      // Analyze authentication pattern for this source
      const successful = sourceEvents.filter(e => e.status === 'Success')
      const failed = sourceEvents.filter(e => e.status === 'Failed')
      const uniqueUsers = new Set(sourceEvents.map(e => e.userName).filter(u => u))

      // Check for password spray characteristics
      if (uniqueUsers.size >= this.thresholds.minTargetUsers &&
          successful.length + failed.length >= this.thresholds.minTotalAttempts) {

        const successRate = successful.length / (successful.length + failed.length)

        // Password spray typically has very low success rate
        if (successRate <= this.thresholds.successToFailureRatio) {

          // Check if failures significantly outnumber successes
          if (failed.length > successful.length) {

            let confidence = 85
            let riskLevel = 'high'

            // Additional risk factors
            if (uniqueUsers.size > 20) confidence += 10
            if (successRate < 0.1) confidence += 10
            if (failed.length > 50) confidence += 10

            // Check for privileged accounts in successful logins
            const successfulPrivileged = successful.filter(login => {
              const userProfile = context.userProfiles?.find(u =>
                u.userName === login.userName && u.domain === login.domainName
              )
              return userProfile?.privileged
            })

            if (successfulPrivileged.length > 0) {
              confidence += 15
              riskLevel = 'critical'
            }

            const anomaly = this.createAnomaly(
              'Password Spray Attack Detected',
              `Source ${sourceIP} attempted authentication against ${uniqueUsers.size} users with ${Math.round(successRate * 100)}% success rate`,
              {
                sourceIP,
                targetUsers: Array.from(uniqueUsers),
                totalAttempts: sourceEvents.length,
                successfulAttempts: successful.length,
                failedAttempts: failed.length,
                successRate: Math.round(successRate * 100),
                uniqueTargets: uniqueUsers.size,
                successfulPrivileged: successfulPrivileged.length,
                targetComputers: Array.from(new Set(sourceEvents.map(e => e.computerName).filter(c => c))),
                timeSpan: this.calculateTimeSpan(sourceEvents),
                authenticationMethods: Array.from(new Set(sourceEvents.map(e => e.logonType).filter(t => t)))
              },
              confidence,
              {
                attackType: 'password_spray',
                riskLevel,
                detectionMethod: 'success_failure_ratio'
              }
            )

            anomalies.push(anomaly)
          }
        }
      }
    })

    return anomalies
  }

  private calculateTimeSpan(events: AuthEvent[]): string {
    if (events.length === 0) return '0 minutes'

    const timestamps = events.map(e => e.timestamp instanceof Date
      ? e.timestamp.getTime()
      : new Date(e.timestamp).getTime()).sort()
    const spanMs = timestamps[timestamps.length - 1] - timestamps[0]
    const spanMinutes = Math.round(spanMs / (1000 * 60))

    return `${spanMinutes} minutes`
  }
}
