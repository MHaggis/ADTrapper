import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext } from '../types'

export class AnonymousAccountRule extends BaseRule {
  private readonly nullSessionUsername = 'ANONYMOUS LOGON'

  constructor() {
    super({
      id: 'anonymous_account_monitoring',
      name: 'Anonymous Account Usage',
      description: 'Detects suspicious usage of anonymous or null session accounts',
      category: 'authentication',
      severity: 'medium',
      timeWindow: 30, // 30 minutes for anonymous activity monitoring
      thresholds: {
        anonymousLogonType: 3, // Network logon type
        suspiciousAnonymousEvents: 5,
        minAnonymousEvents: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects suspicious usage of anonymous or null session accounts that may indicate reconnaissance, unauthorized access attempts, or lateral movement. Anonymous access can be legitimate for certain services but is often a precursor to more serious attacks.',
        detectionLogic: 'Monitors anonymous logon events and account modifications, correlating with IP intelligence to identify suspicious sources. Analyzes successful anonymous network logins and account changes to detect potential reconnaissance or unauthorized system enumeration.',
        falsePositives: 'Legitimate anonymous access to public shares, network discovery tools, monitoring systems, or applications that require anonymous authentication. May also trigger during legitimate network scanning or service discovery activities.',
        mitigation: [
          'Restrict anonymous access to necessary resources only',
          'Disable null session enumeration on domain controllers',
          'Configure restrictive anonymous access policies',
          'Monitor and block anonymous account modifications',
          'Implement network segmentation to limit anonymous access',
          'Use authenticated access for shared resources where possible',
          'Regular audit of anonymous access permissions',
          'Implement IP reputation filtering for anonymous access'
        ],
        windowsEvents: ['4624 (Successful Logon with LogonType=3)', '4625 (Failed Logon)', '4742 (Computer Account Changed)', '5140 (Network Share Access)', '5145 (Detailed Network Share Access)'],
        exampleQuery: `index=windows EventCode=4624 LogonType=3 TargetUserName="ANONYMOUS LOGON" | stats count by IpAddress, Computer | where count > 10`,
        recommendedThresholds: {
          anonymousLogonType: 3,
          suspiciousAnonymousEvents: 5,
          minAnonymousEvents: 1
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Filter anonymous/null session events
    const anonymousEvents = events.filter(event =>
      event.userName === this.nullSessionUsername ||
      event.userName === null ||
      event.userName === '' ||
      event.status === 'Success' // Focus on successful anonymous access
    )

    if (anonymousEvents.length === 0) return anomalies

    // Group by source IP and computer
    const sourceGroups = this.groupBy(anonymousEvents, event =>
      `${event.sourceIp || 'unknown'}|${event.computerName || 'unknown'}`
    )

    Object.entries(sourceGroups).forEach(([groupKey, groupEvents]) => {
      const [sourceIP, computer] = groupKey.split('|')

      if (groupEvents.length >= this.thresholds.suspiciousAnonymousEvents) {

        // Check for successful anonymous logins
        const successfulAnonymous = groupEvents.filter(event =>
          event.status === 'Success' &&
          event.logonType === 'Network'
        )

        if (successfulAnonymous.length > 0) {

          // Check if source IP is suspicious
          const ipInfo = context.ipIntelligence?.find(ip => ip.ip === sourceIP)
          const isSuspiciousSource = ipInfo && (
            ipInfo.isTor ||
            ipInfo.isVpn ||
            ipInfo.isMalicious ||
            ipInfo.riskScore > 70 ||
            !['US', 'CA', 'GB', 'DE', 'FR', 'AU'].includes(ipInfo.country || '')
          )

          let confidence = 60
          let riskLevel = 'medium'

          if (isSuspiciousSource) {
            confidence += 25
            riskLevel = 'high'
          }

          if (successfulAnonymous.length > 10) {
            confidence += 15
            riskLevel = 'high'
          }

          // Check for reconnaissance pattern (multiple different logon types)
          const logonTypes = new Set(groupEvents.map(e => e.logonType).filter(t => t))
          if (logonTypes.size > 2) {
            confidence += 10
          }

          const anomaly = this.createAnomaly(
            'Anonymous Account Access Detected',
            `${successfulAnonymous.length} successful anonymous logins from ${sourceIP} to ${computer}`,
            {
              sourceIP,
              targetComputer: computer,
              totalAnonymousEvents: groupEvents.length,
              successfulAnonymous: successfulAnonymous.length,
              logonTypes: Array.from(logonTypes),
              eventDetails: groupEvents.slice(0, 10).map(event => ({
                timestamp: event.timestamp,
                logonType: event.logonType,
                status: event.status,
                eventId: event.eventId
              })),
              ipIntelligence: ipInfo ? {
                country: ipInfo.country,
                city: ipInfo.city,
                isTor: ipInfo.isTor,
                isVpn: ipInfo.isVpn,
                isMalicious: ipInfo.isMalicious,
                riskScore: ipInfo.riskScore
              } : null,
              isSuspiciousSource
            },
            confidence,
            {
              activityType: 'anonymous_access',
              riskLevel,
              detectionMethod: 'null_session_analysis'
            }
          )

          anomalies.push(anomaly)
        }
      }
    })

    // Also check for anonymous account changes (EventCode 4742)
    const anonymousChanges = events.filter(event =>
      event.eventId === '4742' &&
      event.userName === this.nullSessionUsername
    )

    if (anonymousChanges.length > 0) {
      const uniqueComputers = new Set(anonymousChanges.map(e => e.computerName).filter(c => c))

      const anomaly = this.createAnomaly(
        'Anonymous Account Modification',
        `Anonymous account changes detected on ${uniqueComputers.size} computers`,
        {
          totalChanges: anonymousChanges.length,
          uniqueComputers: Array.from(uniqueComputers),
          changeDetails: anonymousChanges.map(change => ({
            timestamp: change.timestamp,
            computer: change.computerName,
            sourceIP: change.sourceIp
          }))
        },
        75,
        {
          activityType: 'anonymous_modification',
          detectionMethod: 'account_change_analysis'
        }
      )

      anomalies.push(anomaly)
    }

    return anomalies
  }
}
