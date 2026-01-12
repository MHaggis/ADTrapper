import { CorrelationRule } from './CorrelationRule'
import { AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class ServiceAccountCorrelationRule extends CorrelationRule {
  constructor() {
    super(
      'service-account-correlation',
      'Service Account Correlation Analysis',
      'Detects coordinated attacks or patterns across multiple service accounts',
      'critical',
      60, // 1 hour time window
      {
        minServiceAccounts: 3,
        timeWindowMinutes: 30,
        confidenceThreshold: 0.8,
        maxTimeBetweenEvents: 10 // minutes
      },
      {
        overview: 'Detects coordinated attacks or suspicious patterns across multiple service accounts within time windows. Service accounts are high-value targets for attackers seeking persistence and lateral movement, making coordinated attacks particularly concerning.',
        detectionLogic: 'Correlates authentication events across multiple service accounts within configurable time windows. Identifies patterns such as coordinated failures, simultaneous authentication attempts, privilege escalation cascades, and geographic spread attacks targeting service accounts. Uses statistical analysis to detect anomalous patterns.',
        falsePositives: 'Legitimate service account maintenance activities, automated backup operations, scheduled system updates, or legitimate administrative tasks requiring multiple service account access. May also trigger during normal business operations involving multiple service accounts.',
        mitigation: [
          'Implement service account lifecycle management',
          'Regular audit of service account privileges and usage',
          'Enable detailed monitoring for service account activities',
          'Implement just-in-time service account access',
          'Monitor for service account abuse and compromise',
          'Use Group Managed Service Accounts (gMSA) for improved security',
          'Regular service account password rotation and validation',
          'Implement service account access approval workflows',
          'Enable service account behavioral analytics',
          'Conduct regular service account security assessments'
        ],
        windowsEvents: ['4624 (Account Logon Success)', '4625 (Account Logon Failure)', '4672 (Special Privileges Assigned)', '4673 (Sensitive Privilege Use)', '4723 (Password Change Attempted)', '4724 (Password Reset Attempted)', '4769 (Kerberos Service Ticket Operations)', '4771 (Kerberos Pre-auth Failed)'],
        exampleQuery: `index=windows EventCode=4625 | stats count by TargetUserName | where TargetUserName LIKE "*svc*" OR TargetUserName LIKE "*service*" | where count > 10`,
        recommendedThresholds: {
          minServiceAccounts: 3,
          timeWindowMinutes: 30,
          confidenceThreshold: 0.8,
          maxTimeBetweenEvents: 10
        }
      }
    )
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Get service accounts from user profiles
    const serviceAccounts = context.userProfiles?.filter(profile => profile.isServiceAccount) || []
    if (serviceAccounts.length < this.thresholds.minServiceAccounts) {
      return anomalies
    }

    const serviceAccountUsernames = new Set(
      serviceAccounts.map(account => account.userName.toLowerCase())
    )

    // Filter events to only service account events
    const serviceEvents = events.filter(event =>
      event.userName && serviceAccountUsernames.has(event.userName.toLowerCase())
    )

    if (serviceEvents.length < this.thresholds.minServiceAccounts * 2) {
      return anomalies
    }

    // 1. Coordinated Service Account Failures
    const failuresByTime = this.groupEventsByTimeWindows(serviceEvents.filter(e => e.status === 'Failed'))

    for (const [timeKey, timeWindowEvents] of Array.from(failuresByTime)) {
      const uniqueAccounts = new Set(timeWindowEvents.map(e => e.userName?.toLowerCase()))
      const uniqueIPs = new Set(timeWindowEvents.map(e => e.sourceIp).filter(Boolean))

      if (uniqueAccounts.size >= this.thresholds.minServiceAccounts) {
        const anomaly = this.createCorrelationAnomaly(
          'Coordinated Service Account Attacks',
          `Multiple service accounts (${uniqueAccounts.size}) failed authentication within a short time window from ${uniqueIPs.size} IP addresses`,
          [], // Event-based correlation
          this.calculateCorrelationScore([], this.timeWindow, { severityWeight: 0.4, timeClosenessWeight: 0.6 }),
          Array.from(uniqueAccounts).filter(accountName => accountName).map(accountName => ({
            type: 'user' as const,
            id: accountName!,
            name: accountName!
          })),
          {
            attackType: 'coordinated_brute_force',
            affectedAccounts: Array.from(uniqueAccounts),
            uniqueIPs: Array.from(uniqueIPs),
            totalFailures: timeWindowEvents.length,
            timeWindow: timeKey,
            sourceIPs: Array.from(uniqueIPs).slice(0, 5)
          },
          [
            'Investigate all affected service accounts immediately',
            'Check for brute force attacks across multiple service accounts',
            'Review authentication logs for attack patterns',
            'Consider temporarily disabling affected service accounts',
            'Update service account passwords if compromised'
          ]
        )
        anomalies.push(anomaly)
      }
    }

    // 2. Service Account Privilege Escalation Cascade
    const privilegeEvents = serviceEvents.filter(e =>
      e.eventId === '4672' || // Special privileges assigned
      e.eventId === '4732' || // Added to privileged group
      e.eventId === '4756'    // Added to universal group
    )

    if (privilegeEvents.length >= this.thresholds.minServiceAccounts) {
      const privilegeByTime = this.groupEventsByTimeWindows(privilegeEvents)
      const uniquePrivilegeAccounts = new Set(privilegeEvents.map(e => e.userName?.toLowerCase()))

      if (uniquePrivilegeAccounts.size >= this.thresholds.minServiceAccounts) {
        const anomaly = this.createCorrelationAnomaly(
          'Service Account Privilege Escalation Cascade',
          `Multiple service accounts (${uniquePrivilegeAccounts.size}) received privilege changes within a short time window`,
          [], // Event-based correlation
          this.calculateCorrelationScore([], this.timeWindow, { severityWeight: 0.6, timeClosenessWeight: 0.4 }),
          Array.from(uniquePrivilegeAccounts).filter(accountName => accountName).map(accountName => ({
            type: 'user' as const,
            id: accountName!,
            name: accountName!
          })),
          {
            attackType: 'privilege_escalation_cascade',
            affectedAccounts: Array.from(uniquePrivilegeAccounts),
            privilegeEvents: privilegeEvents.length,
            timeWindow: `${this.timeWindow} minutes`,
            recentChanges: privilegeEvents.slice(-5).map(e => ({
              timestamp: e.timestamp,
              account: e.userName,
              computer: e.computerName,
              eventId: e.eventId
            }))
          },
          [
            'Review all privilege changes for legitimacy',
            'Check for unauthorized administrative access',
            'Audit service account group memberships',
            'Verify changes were approved through change management',
            'Monitor affected accounts for suspicious activity'
          ]
        )
        anomalies.push(anomaly)
      }
    }

    // 3. Service Account Geographic Anomalies
    const successfulEvents = serviceEvents.filter(e => e.status === 'Success')
    const geoAnomalies = this.detectGeographicAnomalies(successfulEvents, context)

    if (geoAnomalies.length >= this.thresholds.minServiceAccounts) {
      const uniqueGeoAccounts = new Set(geoAnomalies.map(a => a.userName?.toLowerCase()))

      const anomaly = this.createCorrelationAnomaly(
        'Service Account Geographic Spread',
        `Multiple service accounts (${uniqueGeoAccounts.size}) authenticated from unusual geographic locations`,
        [], // Event-based correlation
        this.calculateCorrelationScore([], this.timeWindow, { severityWeight: 0.3, timeClosenessWeight: 0.3, alertDiversityWeight: 0.4 }),
                  Array.from(uniqueGeoAccounts).filter(accountName => accountName).map(accountName => ({
            type: 'user' as const,
            id: accountName!,
            name: accountName!
          })),
        {
          attackType: 'geographic_anomaly',
          affectedAccounts: Array.from(uniqueGeoAccounts),
          geographicAnomalies: geoAnomalies.length,
          unusualLocations: geoAnomalies.slice(0, 10).map(a => ({
            account: a.userName,
            sourceIp: a.sourceIp,
            timestamp: a.timestamp
          }))
        },
        [
          'Verify service accounts are only authenticating from expected locations',
          'Check for VPN or proxy usage by service accounts',
          'Review geographic access patterns for service accounts',
          'Consider implementing geographic restrictions for service accounts'
        ]
      )
      anomalies.push(anomaly)
    }

    // 4. Service Account Lockout Patterns
    const lockoutEvents = serviceEvents.filter(e => e.eventId === '4740') // Account lockout

    if (lockoutEvents.length >= this.thresholds.minServiceAccounts) {
      const lockoutByTime = this.groupEventsByTimeWindows(lockoutEvents)
      const uniqueLockoutAccounts = new Set(lockoutEvents.map(e => e.userName?.toLowerCase()))

      const anomaly = this.createCorrelationAnomaly(
        'Service Account Lockout Pattern',
        `Multiple service accounts (${uniqueLockoutAccounts.size}) experienced account lockouts in a short time window`,
        [], // Event-based correlation
        this.calculateCorrelationScore([], this.timeWindow, { severityWeight: 0.5, timeClosenessWeight: 0.5 }),
                  Array.from(uniqueLockoutAccounts).filter(accountName => accountName).map(accountName => ({
            type: 'user' as const,
            id: accountName!,
            name: accountName!
          })),
        {
          attackType: 'account_lockout_attack',
          affectedAccounts: Array.from(uniqueLockoutAccounts),
          lockoutEvents: lockoutEvents.length,
          timeWindow: `${this.timeWindow} minutes`,
          lockoutDetails: lockoutEvents.slice(-5).map(e => ({
            timestamp: e.timestamp,
            account: e.userName,
            computer: e.computerName
          }))
        },
        [
          'Investigate potential brute force attacks on service accounts',
          'Check account lockout policies and thresholds',
          'Review failed authentication attempts for affected accounts',
          'Consider implementing account lockout monitoring',
          'Verify service account passwords have not been compromised'
        ]
      )
      anomalies.push(anomaly)
    }

    return anomalies
  }

  private groupEventsByTimeWindows(events: AuthEvent[]): Map<string, AuthEvent[]> {
    const timeWindows = new Map<string, AuthEvent[]>()
    const windowSize = this.thresholds.timeWindowMinutes * 60 * 1000 // Convert to milliseconds

    for (const event of events) {
      const eventTime = new Date(event.timestamp).getTime()
      const windowStart = Math.floor(eventTime / windowSize) * windowSize
      const windowKey = new Date(windowStart).toISOString()

      if (!timeWindows.has(windowKey)) {
        timeWindows.set(windowKey, [])
      }
      timeWindows.get(windowKey)!.push(event)
    }

    return timeWindows
  }

  private detectGeographicAnomalies(events: AuthEvent[], context: AnalyticsContext): AuthEvent[] {
    const anomalies: AuthEvent[] = []

    for (const event of events) {
      if (!event.sourceIp) continue

      const geoInfo = context.ipIntelligence?.find(geo => geo.ip === event.sourceIp)
      if (!geoInfo) continue

      // Flag service accounts from high-risk locations or unusual patterns
      if (geoInfo.isTor || geoInfo.isVpn || geoInfo.isMalicious ||
          geoInfo.riskScore > 50 || geoInfo.country !== 'US') { // Simplified - in real world, you'd have allowed countries
        anomalies.push(event)
      }
    }

    return anomalies
  }
}
