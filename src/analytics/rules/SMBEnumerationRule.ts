import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext } from '../types'

export class SMBEnumerationRule extends BaseRule {
  constructor() {
    super({
      id: 'smb_enumeration_detection',
      name: 'SMB Enumeration Detection',
      description: 'Detects SMB enumeration attempts including user discovery, share enumeration, and null session attacks',
      category: 'network',
      severity: 'high',
      timeWindow: 10, // 10 minutes
      thresholds: {
        uniqueUserAttempts: 20,     // Different usernames tried
        rapidAttemptThreshold: 5,   // Attempts per minute
        nullSessionThreshold: 3,    // Null session connections
        sequentialUserPattern: 10   // Sequential username patterns
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects SMB enumeration attacks including user discovery, share enumeration, and null session attacks. SMB enumeration is a common reconnaissance technique used by attackers to map network resources and discover valid usernames.',
        detectionLogic: 'Analyzes authentication patterns specific to SMB enumeration: (1) Sequential username attempts suggesting automated user discovery, (2) High volume NTLM failures from same source, (3) Anonymous/null session connections, (4) Rapid authentication attempts indicative of automated tools.',
        falsePositives: 'Legitimate network scanning, bulk authentication operations, misconfigured applications, or users attempting multiple usernames during login recovery.',
        mitigation: [
          'Disable NTLM authentication and prefer Kerberos',
          'Restrict anonymous access to SMB shares',
          'Implement account lockout policies',
          'Use SMB signing and encryption',
          'Monitor for unusual authentication patterns',
          'Implement network segmentation',
          'Disable null session enumeration',
          'Use authenticated access for all SMB operations'
        ],
        windowsEvents: ['4625 (Failed Logon)', '4776 (NTLM Authentication)', '4624 (Successful Logon)', '5140 (Network Share Access)', '5145 (Detailed Network Share Access)'],
        exampleQuery: `index=windows EventCode=4776 Status=0xc0000064 | bucket span=5m _time | stats dc(TargetUserName) AS unique_accounts by _time, IpAddress | where unique_accounts > 20`,
        recommendedThresholds: {
          uniqueUserAttempts: 20,
          rapidAttemptThreshold: 5,
          nullSessionThreshold: 3,
          sequentialUserPattern: 10
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // 1. Detect user enumeration via NTLM failures
    const userEnumerationAnomalies = this.detectUserEnumeration(events)
    anomalies.push(...userEnumerationAnomalies)

    // 2. Detect null session enumeration
    const nullSessionAnomalies = this.detectNullSessionEnumeration(events, context)
    anomalies.push(...nullSessionAnomalies)

    // 3. Detect sequential username patterns
    const sequentialAnomalies = this.detectSequentialUserPatterns(events)
    anomalies.push(...sequentialAnomalies)

    // 4. Detect rapid SMB authentication attempts
    const rapidAttemptAnomalies = this.detectRapidSMBAttempts(events)
    anomalies.push(...rapidAttemptAnomalies)

    return anomalies
  }

  private detectUserEnumeration(events: AuthEvent[]): Anomaly[] {
    const anomalies: Anomaly[] = []

    // Focus on NTLM failures (SMB commonly uses NTLM)
    const ntlmFailures = events.filter(event =>
      event.eventId === '4776' &&
      event.status === 'Failed' &&
      event.userName &&
      event.userName !== '*' &&
      event.sourceIp
    )

    if (ntlmFailures.length === 0) return anomalies

    // Group by source IP and time window
    const sourceGroups = this.groupBy(ntlmFailures, event =>
      `${event.sourceIp || 'unknown'}_${Math.floor(new Date(event.timestamp).getTime() / (this.timeWindow * 60 * 1000))}`
    )

    Object.entries(sourceGroups).forEach(([groupKey, groupEvents]) => {
      const uniqueUsers = new Set(groupEvents.map(e => e.userName))
      const sourceIP = groupEvents[0].sourceIp

      if (uniqueUsers.size >= this.thresholds.uniqueUserAttempts) {
        // Check for enumeration patterns
        const invalidUserCount = groupEvents.filter(e =>
          e.failureReason === '0xc0000064' // STATUS_NO_SUCH_USER
        ).length

        const isEnumerationPattern = invalidUserCount > groupEvents.length * 0.7 // 70% invalid users

        if (isEnumerationPattern) {
          const anomaly = this.createAnomaly(
            'SMB User Enumeration Detected',
            `${uniqueUsers.size} unique usernames attempted from ${sourceIP} via NTLM - likely SMB enumeration`,
            {
              sourceIP,
              uniqueUsers: Array.from(uniqueUsers),
              totalAttempts: groupEvents.length,
              invalidUserCount,
              timeWindow: this.timeWindow,
              enumerationPattern: true,
              protocol: 'NTLM/SMB'
            },
            85,
            {
              attackType: 'smb_enumeration',
              detectionMethod: 'user_discovery_pattern'
            }
          )
          anomalies.push(anomaly)
        }
      }
    })

    return anomalies
  }

  private detectNullSessionEnumeration(events: AuthEvent[], context: AnalyticsContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    // Look for anonymous network logins (null sessions)
    const nullSessions = events.filter(event =>
      event.userName === 'ANONYMOUS LOGON' &&
      event.logonType === 'Network' &&
      event.status === 'Success' &&
      event.sourceIp
    )

    if (nullSessions.length === 0) return anomalies

    // Group by source IP
    const sourceGroups = this.groupBy(nullSessions, event => event.sourceIp || 'unknown')

    Object.entries(sourceGroups).forEach(([sourceIP, groupEvents]) => {
      if (groupEvents.length >= this.thresholds.nullSessionThreshold) {
        // Check if source is suspicious
        const ipInfo = context.ipIntelligence?.find(ip => ip.ip === sourceIP)
        const isSuspicious = ipInfo && (
          ipInfo.isTor || ipInfo.isVpn || ipInfo.isMalicious || ipInfo.riskScore > 60
        )

        const anomaly = this.createAnomaly(
          'SMB Null Session Enumeration',
          `${groupEvents.length} anonymous network logins from ${sourceIP} - potential SMB share enumeration`,
          {
            sourceIP,
            nullSessionCount: groupEvents.length,
            targetComputers: Array.from(new Set(groupEvents.map(e => e.computerName))),
            isSuspiciousSource: isSuspicious,
            ipIntelligence: ipInfo
          },
          isSuspicious ? 90 : 75,
          {
            attackType: 'smb_null_session',
            detectionMethod: 'anonymous_network_access'
          }
        )
        anomalies.push(anomaly)
      }
    })

    return anomalies
  }

  private detectSequentialUserPatterns(events: AuthEvent[]): Anomaly[] {
    const anomalies: Anomaly[] = []

    const failedAuths = events.filter(event =>
      event.status === 'Failed' &&
      event.userName &&
      event.sourceIp
    )

    if (failedAuths.length === 0) return anomalies

    // Group by source IP
    const sourceGroups = this.groupBy(failedAuths, event => event.sourceIp || 'unknown')

    Object.entries(sourceGroups).forEach(([sourceIP, groupEvents]) => {
      if (groupEvents.length >= this.thresholds.sequentialUserPattern) {
        const userNames = groupEvents.map(e => e.userName).filter(u => u).sort()

        // Check for sequential patterns (user1, user2, user3, etc.)
        let sequentialCount = 0
        for (let i = 1; i < userNames.length; i++) {
          const prevUser = userNames[i-1]
          const currUser = userNames[i]
          if (prevUser && currUser && this.isSequentialUser(prevUser, currUser)) {
            sequentialCount++
          }
        }

        if (sequentialCount >= 5) { // At least 5 sequential usernames
          const anomaly = this.createAnomaly(
            'SMB Sequential User Enumeration',
            `${sequentialCount} sequential username patterns detected from ${sourceIP} - automated SMB enumeration`,
            {
              sourceIP,
              sequentialPatterns: sequentialCount,
              sampleUsers: userNames.slice(0, 10),
              totalAttempts: groupEvents.length
            },
            80,
            {
              attackType: 'smb_sequential_enumeration',
              detectionMethod: 'username_pattern_analysis'
            }
          )
          anomalies.push(anomaly)
        }
      }
    })

    return anomalies
  }

  private detectRapidSMBAttempts(events: AuthEvent[]): Anomaly[] {
    const anomalies: Anomaly[] = []

    const recentEvents = this.filterByTimeWindow(events)
    const authAttempts = recentEvents.filter(event =>
      event.sourceIp &&
      (event.eventId === '4776' || event.eventId === '4625')
    )

    if (authAttempts.length === 0) return anomalies

    // Group by source IP and calculate attempt frequency
    const sourceGroups = this.groupBy(authAttempts, event => event.sourceIp || 'unknown')

    Object.entries(sourceGroups).forEach(([sourceIP, groupEvents]) => {
      if (groupEvents.length >= 10) { // Minimum threshold for analysis
        const timestamps = groupEvents
          .map(e => new Date(e.timestamp).getTime())
          .sort((a, b) => a - b)

        const timeSpan = timestamps[timestamps.length - 1] - timestamps[0]
        const attemptsPerMinute = (groupEvents.length / timeSpan) * 60 * 1000

        if (attemptsPerMinute >= this.thresholds.rapidAttemptThreshold) {
          const anomaly = this.createAnomaly(
            'Rapid SMB Authentication Attempts',
            `${attemptsPerMinute.toFixed(1)} auth attempts/minute from ${sourceIP} - possible automated SMB enumeration`,
            {
              sourceIP,
              attemptsPerMinute: Math.round(attemptsPerMinute * 10) / 10,
              totalAttempts: groupEvents.length,
              timeSpanMinutes: Math.round(timeSpan / (60 * 1000) * 10) / 10,
              targetUsers: Array.from(new Set(groupEvents.map(e => e.userName).filter(u => u)))
            },
            70,
            {
              attackType: 'smb_rapid_enumeration',
              detectionMethod: 'frequency_analysis'
            }
          )
          anomalies.push(anomaly)
        }
      }
    })

    return anomalies
  }

  private isSequentialUser(user1: string, user2: string): boolean {
    // Check for common sequential patterns
    const patterns = [
      // user1, user2, user3
      (u1: string, u2: string) => {
        const match1 = u1.match(/^(.+)(\d+)$/)
        const match2 = u2.match(/^(.+)(\d+)$/)
        if (match1 && match2 && match1[1] === match2[1]) {
          return parseInt(match2[2]) === parseInt(match1[2]) + 1
        }
        return false
      },
      // admin, administrator
      (u1: string, u2: string) =>
        (u1 === 'admin' && u2 === 'administrator') ||
        (u1 === 'administrator' && u2 === 'admin'),
      // Common username progressions
      (u1: string, u2: string) =>
        ['guest', 'user', 'test', 'temp'].includes(u1.toLowerCase()) &&
        ['guest', 'user', 'test', 'temp'].includes(u2.toLowerCase())
    ]

    return patterns.some(pattern => pattern(user1, user2))
  }
}
