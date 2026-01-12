import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext } from '../types'

export class ExplicitCredentialsRule extends BaseRule {
  constructor() {
    super({
      id: 'explicit_credentials_monitoring',
      name: 'Explicit Credentials Usage',
      description: 'Monitors RunAs/explicit credential usage patterns',
      category: 'authentication',
      severity: 'medium',
      timeWindow: 5, // 5 minutes for credential usage monitoring
      thresholds: {
        uniqueTargetsThreshold: 30,
        minExplicitCredEvents: 5
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Monitors RunAs and explicit credential usage patterns that may indicate privilege escalation, lateral movement, or unauthorized access to other accounts. Explicit credentials usage can be legitimate but is often a red flag when used excessively.',
        detectionLogic: 'Analyzes explicit credential logon events (event 4648) grouped by caller user and time windows. Identifies patterns where a single user accesses many different accounts, particularly when targeting privileged accounts. Also monitors unusual credential usage patterns by computer.',
        falsePositives: 'Legitimate administrative tasks requiring RunAs, service accounts accessing multiple systems, helpdesk personnel assisting users, or automated processes using explicit credentials. May also trigger during system maintenance or application deployment activities.',
        mitigation: [
          'Implement Just-In-Time (JIT) administrative access',
          'Use dedicated service accounts instead of explicit credentials',
          'Monitor and audit all explicit credential usage',
          'Implement principle of least privilege',
          'Use Group Managed Service Accounts (gMSA) for applications',
          'Regular review of explicit credential permissions',
          'Enable credential theft monitoring',
          'Implement session recording for administrative access'
        ],
        windowsEvents: ['4648 (Explicit Credential Logon)', '4672 (Admin Logon)', '4624 (Successful Logon)', '4688 (Process Creation)', '4689 (Process Termination)'],
        exampleQuery: `index=windows EventCode=4648 | bucket span=5m _time | stats dc(TargetUserName) AS unique_accounts by _time, Caller_User_Name | where unique_accounts > 30`,
        recommendedThresholds: {
          uniqueTargetsThreshold: 30,
          minExplicitCredEvents: 5
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Filter explicit credential events (EventCode 4648)
    const explicitCredEvents = events.filter(event =>
      event.eventId === '4648' &&
      event.userName &&
      event.userName !== '*' &&
      event.status === 'Success'
    )

    if (explicitCredEvents.length < this.thresholds.minExplicitCredEvents) return anomalies

    // Group by caller user and time windows
    const callerGroups = this.groupByCallerAndTime(explicitCredEvents)

    Object.entries(callerGroups).forEach(([callerKey, callerEvents]) => {
      const [callerUser, timeWindow] = callerKey.split('|')
      const uniqueTargets = new Set(callerEvents.map(e => e.userName).filter(u => u))

      if (uniqueTargets.size >= this.thresholds.uniqueTargetsThreshold) {

        // Get caller profile to assess risk
        const callerProfile = context.userProfiles?.find(u =>
          u.userName === callerUser.split('\\')[1] &&
          u.domain === callerUser.split('\\')[0]
        )

        let confidence = 70
        let riskLevel = 'medium'

        // Higher risk if caller is privileged
        if (callerProfile?.privileged) {
          confidence += 20
          riskLevel = 'high'
        }

        // Check if targets include privileged accounts
        const privilegedTargets = callerEvents.filter(event => {
          const targetProfile = context.userProfiles?.find(u =>
            u.userName === event.userName && u.domain === event.domainName
          )
          return targetProfile?.privileged
        })

        if (privilegedTargets.length > 0) {
          confidence += 25
          riskLevel = 'high'
        }

        // Check for unusual patterns
        if (uniqueTargets.size > 50) {
          confidence += 15
          riskLevel = 'critical'
        }

        const anomaly = this.createAnomaly(
          'Excessive Explicit Credentials Usage',
          `User ${callerUser} used explicit credentials to access ${uniqueTargets.size} different accounts`,
          {
            callerUser,
            uniqueTargets: Array.from(uniqueTargets),
            totalEvents: callerEvents.length,
            privilegedTargets: privilegedTargets.length,
            timeWindow,
            targetBreakdown: Array.from(uniqueTargets).map(target => ({
              targetUser: target,
              accessCount: callerEvents.filter(e => e.userName === target).length
            })),
            sourceComputers: Array.from(new Set(callerEvents.map(e => e.computerName).filter(c => c))),
            callerProfile: callerProfile ? {
              department: callerProfile.department,
              privileged: callerProfile.privileged,
              title: callerProfile.title
            } : null
          },
          confidence,
          {
            activityType: 'explicit_credentials',
            riskLevel,
            detectionMethod: 'target_count_analysis'
          }
        )

        anomalies.push(anomaly)
      }
    })

    // Also detect unusual explicit credential patterns by computer
    const computerGroups = this.groupBy(explicitCredEvents, event => event.computerName || 'unknown')

    Object.entries(computerGroups).forEach(([computer, computerEvents]) => {
      if (computer === 'unknown') return

      const uniqueCallers = new Set(computerEvents.map(e => `${e.domainName || 'LOCAL'}\\${e.userName}`).filter(u => u))

      if (computerEvents.length >= this.thresholds.minExplicitCredEvents && uniqueCallers.size >= 3) {

        const anomaly = this.createAnomaly(
          'Unusual Explicit Credentials on Computer',
          `Computer ${computer} had ${computerEvents.length} explicit credential events from ${uniqueCallers.size} different callers`,
          {
            computer,
            totalEvents: computerEvents.length,
            uniqueCallers: Array.from(uniqueCallers),
            eventDetails: computerEvents.slice(0, 10).map(event => ({
              timestamp: event.timestamp,
              caller: `${event.domainName || 'LOCAL'}\\${event.userName}`,
              target: event.userName
            }))
          },
          65,
          {
            activityType: 'computer_explicit_creds',
            detectionMethod: 'computer_analysis'
          }
        )

        anomalies.push(anomaly)
      }
    })

    return anomalies
  }

  private groupByCallerAndTime(events: AuthEvent[]): Record<string, AuthEvent[]> {
    const groups: Record<string, AuthEvent[]> = {}

    events.forEach(event => {
      const callerKey = `${event.domainName || 'LOCAL'}\\${event.userName}`

      // Handle both Date objects and string timestamps
      const timestamp = event.timestamp instanceof Date
        ? event.timestamp.getTime()
        : new Date(event.timestamp).getTime()

      // Create 5-minute time windows
      const windowStart = Math.floor(timestamp / (5 * 60 * 1000)) * (5 * 60 * 1000)
      const timeWindow = new Date(windowStart).toISOString()

      const key = `${callerKey}|${timeWindow}`

      if (!groups[key]) {
        groups[key] = []
      }
      groups[key].push(event)
    })

    return groups
  }
}
