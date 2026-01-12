import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext } from '../types'

export class NTLMAuthenticationRule extends BaseRule {
  private readonly invalidUserStatus = '0xc0000064' // STATUS_NO_SUCH_USER
  private readonly wrongPasswordStatus = '0xC000006A' // STATUS_WRONG_PASSWORD

  constructor() {
    super({
      id: 'ntlm_authentication_failures',
      name: 'NTLM Authentication Failures',
      description: 'Detects multiple invalid users failing NTLM authentication from the same source',
      category: 'authentication',
      severity: 'high',
      timeWindow: 5, // 5 minutes to match Splunk query
      thresholds: {
        uniqueAccountsThreshold: 30
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects multiple invalid users failing NTLM authentication from the same source, which may indicate account enumeration, username harvesting, or brute force attacks. NTLM is often targeted because it lacks the security features of Kerberos.',
        detectionLogic: 'Analyzes NTLM authentication failures (event 4776) grouped by source IP and time windows. Identifies patterns where a single source attempts authentication against many unique usernames, particularly focusing on invalid username failures (STATUS_NO_SUCH_USER) vs wrong password failures.',
        falsePositives: 'Legacy applications using NTLM for compatibility, misconfigured clients, network scanning tools, or users with memory issues attempting multiple usernames. May also trigger during legitimate bulk operations or testing scenarios.',
        mitigation: [
          'Disable NTLM authentication where possible (prefer Kerberos)',
          'Implement NTLM auditing and blocking policies',
          'Configure account lockout policies for NTLM failures',
          'Monitor for NTLM relay attacks and downgrade attempts',
          'Upgrade legacy applications to use modern authentication',
          'Implement network-level authentication (NLA) for RDP',
          'Use Extended Protection for Authentication (EPA)',
          'Regular review and cleanup of NTLM usage'
        ],
        windowsEvents: ['4776 (NTLM Authentication)', '4625 (Failed Logon)', '4771 (Kerberos Pre-auth Failed)', '4648 (Explicit Credential Logon)', '4874 (NTLM Authentication Blocked)'],
        exampleQuery: `index=windows EventCode=4776 TargetUserName!=*$ Status=0xc0000064 | bucket span=5m _time | stats dc(TargetUserName) AS unique_accounts by _time, Workstation | where unique_accounts > 30`,
        recommendedThresholds: {
          uniqueAccountsThreshold: 30
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Filter NTLM authentication failures (EventCode 4776)
    const ntlmFailures = events.filter(event =>
      event.eventId === '4776' &&
      event.status === 'Failed' &&
      event.userName &&
      event.userName !== '*' &&
      event.sourceIp
    )

    if (ntlmFailures.length === 0) return anomalies

    // Group by source (workstation) and time windows
    const sourceGroups = this.groupBySourceAndTime(ntlmFailures)

    Object.entries(sourceGroups).forEach(([sourceKey, sourceEvents]) => {
      const [sourceIP, timeWindow] = sourceKey.split('|')
      const uniqueUsers = new Set(sourceEvents.map(e => e.userName).filter(u => u))

      if (uniqueUsers.size >= this.thresholds.uniqueAccountsThreshold) {
        // Check for invalid user vs wrong password patterns
        const invalidUsers = sourceEvents.filter(e =>
          e.failureReason === this.invalidUserStatus
        )
        const wrongPasswords = sourceEvents.filter(e =>
          e.failureReason === this.wrongPasswordStatus
        )

        let confidence = 80
        let description = `${uniqueUsers.size} unique users failed NTLM authentication from ${sourceIP}`

        if (invalidUsers.length > wrongPasswords.length) {
          confidence += 10
          description += ` (primarily invalid usernames)`
        } else {
          description += ` (primarily wrong passwords)`
        }

        // Check if this is a scanning/brute force pattern
        if (uniqueUsers.size > 50) {
          confidence += 20
          description += ' - High volume suggests automated scanning'
        }

        const anomaly = this.createAnomaly(
          'NTLM Authentication Attack Detected',
          description,
          {
            sourceIP,
            uniqueUsers: Array.from(uniqueUsers),
            totalFailures: sourceEvents.length,
            invalidUserCount: invalidUsers.length,
            wrongPasswordCount: wrongPasswords.length,
            timeWindow,
            workstations: Array.from(new Set(sourceEvents.map(e => e.computerName).filter(c => c))),
            failureReasons: Array.from(new Set(sourceEvents.map(e => e.failureReason).filter(r => r)))
          },
          confidence,
          {
            attackType: 'ntlm_enumeration',
            detectionMethod: 'multiple_invalid_users'
          }
        )

        anomalies.push(anomaly)
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
