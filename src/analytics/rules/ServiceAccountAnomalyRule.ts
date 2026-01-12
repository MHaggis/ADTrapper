import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext } from '../types'

export class ServiceAccountAnomalyRule extends BaseRule {
  constructor() {
    super({
      id: 'service_account_anomaly_detection',
      name: 'Service Account Anomaly Detection',
      description: 'Detects suspicious activities and security issues with service accounts',
      category: 'authentication',
      severity: 'high',
      timeWindow: 168, // 1 week (service accounts have different patterns)
      thresholds: {
        maxFailedLogins: 10, // Service accounts should rarely fail authentication
        maxConcurrentSessions: 5, // Service accounts may have multiple sessions but not unlimited
        unusualHourThreshold: 0.7, // Flag if service account activity is unusual for the time
        geographicSpreadThreshold: 3, // Service accounts should authenticate from limited locations
        passwordChangeThreshold: 30, // Days between password changes for service accounts
        accountAgeThreshold: 365 // Flag service accounts older than this without review
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects suspicious activities and security issues with service accounts that deviate from expected patterns. Service accounts should have predictable, limited authentication patterns, so anomalies can indicate compromise, misuse, or security policy violations.',
        detectionLogic: 'Analyzes service account authentication patterns including failed logins, geographic spread, unusual hours, concurrent sessions, password change frequency, and account lifecycle. Compares observed behavior against expected service account patterns and flags deviations that may indicate security issues.',
        falsePositives: 'Legitimate service account usage for system administration, automated processes, or scheduled tasks. May also trigger during legitimate service account maintenance, password rotation, or system updates. Normal variations in service account behavior due to workload changes.',
        mitigation: [
          'Immediately investigate suspicious service account activity',
          'Review service account authentication failures and causes',
          'Limit service account geographic access to authorized locations',
          'Monitor service account concurrent sessions and usage patterns',
          'Implement service account password rotation policies',
          'Regular review of service account privileges and access',
          'Enable service account activity monitoring and alerting',
          'Conduct forensic analysis of compromised service accounts',
          'Implement multi-factor authentication for service account access',
          'Regular security assessments of service account configurations'
        ],
        windowsEvents: ['4624 (Account Logon Success)', '4625 (Account Logon Failure)', '4672 (Special Privileges Assigned)', '4723 (Password Change Attempted)', '4724 (Password Reset Attempted)', '4738 (User Account Changed)', '4776 (NTLM Authentication)', '4648 (Explicit Credential Logon)', '4634 (Account Logoff)', '4675 (SIDs Filtered)', '4964 (Special Groups Logon)'],
        exampleQuery: `index=windows EventCode=4625 OR EventCode=4624 | stats count by TargetUserName, LogonType | where LogonType=3`,
        recommendedThresholds: {
          maxFailedLogins: 10,
          maxConcurrentSessions: 5,
          unusualHourThreshold: 0.7,
          geographicSpreadThreshold: 3,
          passwordChangeThreshold: 30,
          accountAgeThreshold: 365
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    const recentEvents = this.filterByTimeWindow(events)

    // Group events by user to analyze patterns
    const eventsByUser = this.groupBy(recentEvents, event => event.userName || 'unknown')

    for (const [userName, userEvents] of Object.entries(eventsByUser)) {
      if (!userName || userName === 'unknown') continue

      // Check if this is a service account from user profiles
      const userProfile = context.userProfiles?.find(profile =>
        profile.userName.toLowerCase() === userName.toLowerCase()
      )

      if (!userProfile?.isServiceAccount) continue

      // Analyze service account patterns
      const serviceAnomalies = this.analyzeServiceAccount(userName, userEvents, userProfile, context)
      anomalies.push(...serviceAnomalies)
    }

    return anomalies
  }

  private analyzeServiceAccount(
    userName: string,
    events: AuthEvent[],
    userProfile: any,
    context: AnalyticsContext
  ): Anomaly[] {
    const anomalies: Anomaly[] = []

    // 1. Service Account Authentication Failures
    const failedEvents = events.filter(e => e.status === 'Failed')
    if (failedEvents.length >= this.thresholds.maxFailedLogins) {
      const confidence = failedEvents.length >= this.thresholds.maxFailedLogins * 2 ? 90 :
                         failedEvents.length >= this.thresholds.maxFailedLogins ? 75 : 60

      const anomaly = this.createAnomaly(
        'Service Account Authentication Failures',
        `Service account ${userName} has ${failedEvents.length} authentication failures, which is unusual for service accounts`,
        {
          userName,
          failedAttempts: failedEvents.length,
          totalAttempts: events.length,
          failureRate: (failedEvents.length / events.length * 100).toFixed(1) + '%',
          serviceAccountType: userProfile.serviceAccountType,
          recentFailures: failedEvents.slice(-5).map(e => ({
            timestamp: e.timestamp,
            sourceIp: e.sourceIp,
            computerName: e.computerName
          }))
        },
        confidence
      )
      anomalies.push(anomaly)
    }

    // 2. Service Account Geographic Spread
    const uniqueIPs = new Set(events.map(e => e.sourceIp).filter(Boolean))
    const uniqueLocations = new Set<string>()

    for (const ip of Array.from(uniqueIPs)) {
      const geoInfo = context.ipIntelligence?.find(geo => geo.ip === ip)
      if (geoInfo?.country) {
        uniqueLocations.add(`${geoInfo.country}-${geoInfo.city || 'Unknown'}`)
      }
    }

    if (uniqueLocations.size >= this.thresholds.geographicSpreadThreshold) {
      const confidence = uniqueLocations.size >= this.thresholds.geographicSpreadThreshold * 2 ? 85 : 70

      const anomaly = this.createAnomaly(
        'Service Account Geographic Spread',
        `Service account ${userName} authenticated from ${uniqueLocations.size} different locations: ${Array.from(uniqueLocations).join(', ')}`,
        {
          userName,
          uniqueLocations: Array.from(uniqueLocations),
          locationCount: uniqueLocations.size,
          serviceAccountType: userProfile.serviceAccountType,
          recentIPs: Array.from(uniqueIPs).slice(-5)
        },
        confidence
      )
      anomalies.push(anomaly)
    }

    // 3. Service Account Unusual Hours
    const successfulEvents = events.filter(e => e.status === 'Success')
    const unusualHourEvents = this.detectUnusualHours(successfulEvents, userProfile)

    if (unusualHourEvents.length > 0) {
      const confidence = unusualHourEvents.length >= successfulEvents.length * 0.5 ? 65 : 50

      const anomaly = this.createAnomaly(
        'Service Account Unusual Hours',
        `Service account ${userName} authenticated during unusual hours (${unusualHourEvents.length} events)`,
        {
          userName,
          unusualEvents: unusualHourEvents.length,
          totalSuccessful: successfulEvents.length,
          serviceAccountType: userProfile.serviceAccountType,
          unusualHours: unusualHourEvents.map(e => ({
            timestamp: e.timestamp,
            hour: new Date(e.timestamp).getHours(),
            sourceIp: e.sourceIp
          }))
        },
        confidence
      )
      anomalies.push(anomaly)
    }

    // 4. Service Account Concurrent Sessions
    const concurrentSessions = this.detectConcurrentSessions(events)
    if (concurrentSessions.maxConcurrent >= this.thresholds.maxConcurrentSessions) {
      const confidence = concurrentSessions.maxConcurrent >= this.thresholds.maxConcurrentSessions * 2 ? 80 : 65

      const anomaly = this.createAnomaly(
        'Service Account High Concurrent Sessions',
        `Service account ${userName} has ${concurrentSessions.maxConcurrent} concurrent sessions (threshold: ${this.thresholds.maxConcurrentSessions})`,
        {
          userName,
          maxConcurrent: concurrentSessions.maxConcurrent,
          totalSessions: concurrentSessions.totalSessions,
          serviceAccountType: userProfile.serviceAccountType,
          sessionDetails: concurrentSessions.sessionDetails
        },
        confidence
      )
      anomalies.push(anomaly)
    }

    // 5. Service Account Age Alert
    if (userProfile.accountAgeDays && userProfile.accountAgeDays > this.thresholds.accountAgeThreshold) {
      const confidence = userProfile.accountAgeDays > this.thresholds.accountAgeThreshold * 2 ? 60 : 45

      const anomaly = this.createAnomaly(
        'Service Account Age Review',
        `Service account ${userName} is ${userProfile.accountAgeDays} days old and may need security review`,
        {
          userName,
          accountAgeDays: userProfile.accountAgeDays,
          serviceAccountType: userProfile.serviceAccountType,
          indicators: userProfile.serviceAccountIndicators,
          lastLogon: userProfile.lastLogonDate
        },
        confidence
      )
      anomalies.push(anomaly)
    }

    // 6. Service Account Privilege Escalation Detection
    const privilegeEvents = events.filter(e =>
      e.eventId === '4672' || // Special privileges assigned
      e.eventId === '4732' || // Added to privileged group
      e.eventId === '4756'    // Added to universal group
    )

    if (privilegeEvents.length > 0) {
      const confidence = privilegeEvents.length >= 5 ? 85 : privilegeEvents.length >= 3 ? 75 : 65

      const anomaly = this.createAnomaly(
        'Service Account Privilege Change',
        `Service account ${userName} had ${privilegeEvents.length} privilege-related events`,
        {
          userName,
          privilegeEvents: privilegeEvents.length,
          serviceAccountType: userProfile.serviceAccountType,
          recentChanges: privilegeEvents.slice(-3).map(e => ({
            timestamp: e.timestamp,
            eventId: e.eventId,
            computerName: e.computerName
          }))
        },
        confidence
      )
      anomalies.push(anomaly)
    }

    return anomalies
  }

  private detectUnusualHours(events: AuthEvent[], userProfile: any): AuthEvent[] {
    const unusualEvents: AuthEvent[] = []

    for (const event of events) {
      const eventHour = new Date(event.timestamp).getHours()

      // Service accounts typically run 24/7, but flag if they're outside expected hours
      // For service accounts, we expect more consistent patterns
      const normalHours = userProfile.normalLoginHours || { start: 0, end: 23 }

      if (eventHour < normalHours.start || eventHour > normalHours.end) {
        unusualEvents.push(event)
      }
    }

    return unusualEvents
  }

  private detectConcurrentSessions(events: AuthEvent[]): {
    maxConcurrent: number
    totalSessions: number
    sessionDetails: any[]
  } {
    const sessions: Array<{ start: Date; end?: Date; sourceIp: string }> = []

    for (const event of events) {
      if (event.status === 'Success') {
        sessions.push({
          start: new Date(event.timestamp),
          sourceIp: event.sourceIp || 'unknown'
        })
      } else if (event.status === 'Logoff' && sessions.length > 0) {
        // Match logoff to most recent login from same IP
        const recentSession = sessions
          .filter(s => !s.end && s.sourceIp === (event.sourceIp || 'unknown'))
          .sort((a, b) => b.start.getTime() - a.start.getTime())[0]

        if (recentSession) {
          recentSession.end = new Date(event.timestamp)
        }
      }
    }

    // Calculate concurrent sessions at each point
    let maxConcurrent = 0
    const timePoints = new Map<number, number>()

    for (const session of sessions) {
      const startTime = session.start.getTime()
      const endTime = session.end?.getTime() || Date.now()

      // Increment at start
      timePoints.set(startTime, (timePoints.get(startTime) || 0) + 1)
      // Decrement at end
      timePoints.set(endTime, (timePoints.get(endTime) || 0) - 1)
    }

    let currentConcurrent = 0
    const sortedTimes = Array.from(timePoints.entries()).sort(([a], [b]) => a - b)

    for (const [time, change] of sortedTimes) {
      currentConcurrent += change
      maxConcurrent = Math.max(maxConcurrent, currentConcurrent)
    }

    return {
      maxConcurrent,
      totalSessions: sessions.length,
      sessionDetails: sessions.slice(-5).map(s => ({
        start: s.start,
        end: s.end,
        sourceIp: s.sourceIp
      }))
    }
  }

  private calculateSeverity(value: number, threshold: number): 'low' | 'medium' | 'high' | 'critical' {
    const ratio = value / threshold

    if (ratio >= 3) return 'critical'
    if (ratio >= 2) return 'high'
    if (ratio >= 1.5) return 'medium'
    return 'low'
  }
}
