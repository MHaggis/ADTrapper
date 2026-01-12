import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext } from '../types'

export class LocalAdminAttacksRule extends BaseRule {
  private readonly adminUsernames = ['administrator', 'admin', 'root', 'sa']

  constructor() {
    super({
      id: 'local_admin_credential_stuffing',
      name: 'Local Administrator Credential Stuffing',
      description: 'Detects credential stuffing attacks targeting local administrator accounts',
      category: 'authentication',
      severity: 'critical',
      timeWindow: 5, // 5 minutes for attack detection
      thresholds: {
        uniqueTargetsThreshold: 30,
        minFailedAttempts: 10
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects credential stuffing attacks targeting local administrator accounts across multiple systems. Local administrator accounts are prime targets for lateral movement attacks as they provide full control over individual computers and enable Pass-the-Hash attacks throughout the domain.',
        detectionLogic: 'Analyzes authentication events targeting common administrator usernames (administrator, admin, root, sa) across multiple computers from single source IPs. Identifies credential stuffing patterns where attackers attempt known passwords against administrator accounts on numerous systems, and detects rapid-fire attempts indicating automated attacks.',
        falsePositives: 'Legitimate administrative tasks accessing multiple systems, automated scripts using administrator credentials, system management tools, or helpdesk personnel troubleshooting multiple machines. May also trigger during legitimate bulk operations or software deployments.',
        mitigation: [
          'Implement Local Administrator Password Solution (LAPS)',
          'Disable or rename default administrator accounts',
          'Use unique local administrator passwords on each system',
          'Implement restricted admin mode for RDP',
          'Monitor for Pass-the-Hash attacks and lateral movement',
          'Use Group Policy to manage local administrator privileges',
          'Implement Just Enough Administration (JEA) for PowerShell',
          'Regular local administrator password rotation',
          'Use Microsoft Defender for Identity to detect lateral movement',
          'Implement network segmentation to limit lateral movement'
        ],
        windowsEvents: ['4624 (Successful Logon)', '4625 (Failed Logon)', '4648 (Explicit Credential Logon)', '4672 (Admin Logon)', '4776 (NTLM Authentication)', '5140 (Network Share Access)'],
        exampleQuery: `index=windows EventCode=4625 TargetUserName="*admin*" | stats count by IpAddress, TargetUserName | where count > 50`,
        recommendedThresholds: {
          uniqueTargetsThreshold: 30,
          minFailedAttempts: 10
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Filter events targeting administrator accounts
    const adminTargetedEvents = events.filter(event => {
      const username = event.userName?.toLowerCase()
      return username && this.adminUsernames.some(admin =>
        username.includes(admin) || admin.includes(username)
      )
    })

    if (adminTargetedEvents.length < this.thresholds.minFailedAttempts) return anomalies

    // Group by source IP and time windows
    const sourceGroups = this.groupBySourceAndTime(adminTargetedEvents)

    Object.entries(sourceGroups).forEach(([sourceKey, sourceEvents]) => {
      const [sourceIP, timeWindow] = sourceKey.split('|')

      const uniqueComputers = new Set(sourceEvents.map(e => e.computerName).filter(c => c))
      const successful = sourceEvents.filter(e => e.status === 'Success')
      const failed = sourceEvents.filter(e => e.status === 'Failed')

      // Check for credential stuffing pattern
      if (uniqueComputers.size >= this.thresholds.uniqueTargetsThreshold ||
          (failed.length >= this.thresholds.minFailedAttempts && successful.length > 0)) {

        let confidence = 80
        let attackType = 'credential_stuffing'

        // Higher confidence for widespread attacks
        if (uniqueComputers.size > 50) confidence += 20
        if (successful.length > 0) confidence += 25

        // Check if successful logins occurred after failed attempts
        const successfulAfterFailed = successful.some(success => {
          const successTime = this.getTimestampMs(success.timestamp)

          return failed.some(failure => {
            const failureTime = this.getTimestampMs(failure.timestamp)
            return failureTime < successTime
          })
        })

        if (successfulAfterFailed) {
          confidence += 15
          attackType = 'successful_credential_stuffing'
        }

        const anomaly = this.createAnomaly(
          'Local Administrator Credential Stuffing',
          `Administrator credential stuffing detected from ${sourceIP} targeting ${uniqueComputers.size} computers`,
          {
            sourceIP,
            uniqueComputers: Array.from(uniqueComputers),
            totalAttempts: sourceEvents.length,
            successfulAttempts: successful.length,
            failedAttempts: failed.length,
            adminUsernames: this.adminUsernames,
            timeWindow,
            successfulAfterFailed,
            computerBreakdown: Array.from(uniqueComputers).map(computer => ({
              computer,
              attempts: sourceEvents.filter(e => e.computerName === computer).length,
              successful: sourceEvents.filter(e => e.computerName === computer && e.status === 'Success').length,
              failed: sourceEvents.filter(e => e.computerName === computer && e.status === 'Failed').length
            })),
            ipIntelligence: context.ipIntelligence?.find(ip => ip.ip === sourceIP)
          },
          confidence,
          {
            attackType,
            targetAccounts: 'local_administrators',
            detectionMethod: 'pattern_analysis'
          }
        )

        anomalies.push(anomaly)
      }
    })

    // Also check for rapid administrator authentication attempts
    const rapidAdminAttempts = this.detectRapidAdminAttempts(adminTargetedEvents)

    rapidAdminAttempts.forEach(attempt => {
      const anomaly = this.createAnomaly(
        'Rapid Administrator Authentication Attempts',
        `Rapid administrator authentication attempts detected: ${attempt.events.length} attempts in ${attempt.durationMinutes} minutes`,
        {
          sourceIP: attempt.sourceIP,
          totalAttempts: attempt.events.length,
          durationMinutes: attempt.durationMinutes,
          attemptsPerMinute: Math.round(attempt.events.length / attempt.durationMinutes),
          computers: Array.from(new Set(attempt.events.map(e => e.computerName).filter(c => c))),
          successRate: Math.round((attempt.events.filter(e => e.status === 'Success').length / attempt.events.length) * 100)
        },
        85,
        {
          attackType: 'rapid_admin_attempts',
          detectionMethod: 'velocity_analysis'
        }
      )

      anomalies.push(anomaly)
    })

    return anomalies
  }

  private groupBySourceAndTime(events: AuthEvent[]): Record<string, AuthEvent[]> {
    const groups: Record<string, AuthEvent[]> = {}

    events.forEach(event => {
      if (!event.sourceIp) return

      // Handle both Date objects and string timestamps
      const timestamp = this.getTimestampMs(event.timestamp)

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

  private detectRapidAdminAttempts(events: AuthEvent[]): Array<{
    sourceIP: string
    events: AuthEvent[]
    durationMinutes: number
  }> {
    const rapidAttempts: Array<{
      sourceIP: string
      events: AuthEvent[]
      durationMinutes: number
    }> = []

    // Group by source IP
    const sourceGroups = this.groupBy(events, event => event.sourceIp || 'unknown')

    Object.entries(sourceGroups).forEach(([sourceIP, sourceEvents]) => {
      if (sourceIP === 'unknown' || sourceEvents.length < 10) return

      // Sort by timestamp - ensure timestamps are Date objects
      const sortedEvents = sourceEvents.sort((a, b) => {
        const aTime = this.getTimestampMs(a.timestamp)
        const bTime = this.getTimestampMs(b.timestamp)
        return aTime - bTime
      })

      // Check for rapid bursts (more than 10 attempts in 5 minutes)
      for (let i = 0; i < sortedEvents.length - 9; i++) {
        const window = sortedEvents.slice(i, i + 10)
        const lastTime = this.getTimestampMs(window[window.length - 1].timestamp)
        const firstTime = this.getTimestampMs(window[0].timestamp)
        const durationMs = lastTime - firstTime
        const durationMinutes = durationMs / (1000 * 60)

        if (durationMinutes <= 5) {
          rapidAttempts.push({
            sourceIP,
            events: window,
            durationMinutes: Math.round(durationMinutes * 10) / 10
          })
          break // Only report one rapid burst per source
        }
      }
    })

    return rapidAttempts
  }
}
