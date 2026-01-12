import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext } from '../types'

export class RDPActivityRule extends BaseRule {
  constructor() {
    super({
      id: 'rdp_activity_monitoring',
      name: 'RDP Activity Monitoring',
      description: 'Monitors Remote Desktop Protocol authentication events and patterns',
      category: 'network',
      severity: 'medium',
      timeWindow: 60, // 1 hour for RDP monitoring
      thresholds: {
        rdpLogonType: 10, // RDP logon type
        suspiciousRDPSources: 1, // Flag any RDP from suspicious sources
        multipleRDPSessions: 3 // Multiple RDP sessions from same source
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Monitors Remote Desktop Protocol (RDP) authentication events and usage patterns to detect potential lateral movement, unauthorized access, and suspicious remote access activity. RDP is a primary attack vector for initial access and lateral movement in enterprise networks.',
        detectionLogic: 'Analyzes RDP authentication events (LogonType=10) to identify multiple RDP sessions from single sources, access from suspicious geographic locations, concurrent sessions from different users, and burst patterns indicating automated scanning or exploitation attempts.',
        falsePositives: 'Legitimate remote work, system administration, helpdesk support, automated monitoring tools, or IT personnel accessing multiple systems for maintenance. May also trigger during legitimate remote access scenarios or monitoring activities.',
        mitigation: [
          'Implement Network Level Authentication (NLA) for RDP',
          'Use Restricted Admin mode to prevent credential theft',
          'Configure RDP gateway for secure remote access',
          'Implement multi-factor authentication for RDP access',
          'Monitor RDP sessions with recording and alerting',
          'Use IP-based restrictions and geolocation policies',
          'Implement session limits and concurrent connection controls',
          'Regular RDP configuration auditing and hardening',
          'Use VPN for remote access instead of direct RDP',
          'Monitor for RDP-based attacks (BlueKeep, RDP relay)'
        ],
        windowsEvents: ['4624 (Successful Logon - LogonType=10)', '4625 (Failed Logon)', '4778 (Session Reconnect)', '4779 (Session Disconnect)', '21 (Remote Desktop Services: Session logon succeeded)', '24 (Remote Desktop Services: Session logon failed)'],
        exampleQuery: `index=windows EventCode=4624 LogonType=10 | stats count by IpAddress, TargetUserName | where count > 5`,
        recommendedThresholds: {
          rdpLogonType: 10,
          suspiciousRDPSources: 1,
          multipleRDPSessions: 3
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Filter RDP authentication events (LogonType=10)
    const rdpEvents = events.filter(event =>
      event.logonType === 'RemoteInteractive' &&
      event.status === 'Success'
    )

    if (rdpEvents.length === 0) return anomalies

    // Group by source IP
    const sourceGroups = this.groupBy(rdpEvents, event => event.sourceIp || 'unknown')

    Object.entries(sourceGroups).forEach(([sourceIP, sourceEvents]) => {
      if (sourceIP === 'unknown') return

      const uniqueUsers = new Set(sourceEvents.map(e => e.userName).filter(u => u))
      const uniqueComputers = new Set(sourceEvents.map(e => e.computerName).filter(c => c))

      // Check for multiple RDP sessions from same source
      if (sourceEvents.length >= this.thresholds.multipleRDPSessions) {

        // Check if source IP is suspicious
        const ipInfo = context.ipIntelligence?.find(ip => ip.ip === sourceIP)
        const isSuspiciousSource = ipInfo && (
          ipInfo.isTor ||
          ipInfo.isVpn ||
          ipInfo.isMalicious ||
          ipInfo.riskScore > 70 ||
          !['US', 'CA', 'GB', 'DE', 'FR', 'AU'].includes(ipInfo.country || '') // Common business countries
        )

        let confidence = 60
        let riskLevel = 'medium'

        if (isSuspiciousSource) {
          confidence += 25
          riskLevel = 'high'
        }

        if (uniqueUsers.size > 1) {
          confidence += 15
          riskLevel = 'high'
        }

        if (sourceEvents.length > 10) {
          confidence += 10
        }

        // Check for privileged users in RDP sessions
        const privilegedUsers = sourceEvents.filter(event => {
          const userProfile = context.userProfiles?.find(u =>
            u.userName === event.userName && u.domain === event.domainName
          )
          return userProfile?.privileged
        })

        if (privilegedUsers.length > 0) {
          confidence += 20
          riskLevel = 'critical'
        }

        const anomaly = this.createAnomaly(
          'RDP Session Activity Detected',
          `${sourceEvents.length} RDP sessions from ${sourceIP} targeting ${uniqueComputers.size} computers`,
          {
            sourceIP,
            totalSessions: sourceEvents.length,
            uniqueUsers: Array.from(uniqueUsers),
            uniqueComputers: Array.from(uniqueComputers),
            privilegedUsers: privilegedUsers.length,
            sessionDetails: sourceEvents.map(session => ({
              timestamp: session.timestamp,
              user: session.userName,
              computer: session.computerName,
              isPrivileged: privilegedUsers.some(pu => pu.userName === session.userName)
            })),
            geoInfo: ipInfo ? {
              country: ipInfo.country,
              city: ipInfo.city,
              isTor: ipInfo.isTor,
              isVpn: ipInfo.isVpn,
              riskScore: ipInfo.riskScore
            } : null,
            isSuspiciousSource
          },
          confidence,
          {
            activityType: 'rdp_sessions',
            riskLevel,
            detectionMethod: 'session_analysis'
          }
        )

        anomalies.push(anomaly)
      }
    })

    // Also check for RDP logon session establishments (EventCode 4624, LogonType=10)
    const rdpLogons = events.filter(event =>
      event.eventId === '4624' &&
      event.logonType === 'RemoteInteractive'
    )

    if (rdpLogons.length > 0) {
      // Group by time windows to detect RDP bursts
      const timeWindows = this.groupByTimeWindows(rdpLogons, 5) // 5-minute windows

      Object.entries(timeWindows).forEach(([timeWindow, windowEvents]) => {
        if (windowEvents.length >= 5) { // 5+ RDP logons in 5 minutes
          const uniqueSources = new Set(windowEvents.map(e => e.sourceIp).filter(ip => ip))

          if (uniqueSources.size >= 2) { // Multiple sources
            const anomaly = this.createAnomaly(
              'RDP Login Burst Detected',
              `${windowEvents.length} RDP logins from ${uniqueSources.size} sources in 5-minute window`,
              {
                timeWindow,
                totalLogins: windowEvents.length,
                uniqueSources: Array.from(uniqueSources),
                sourceBreakdown: Array.from(uniqueSources).map(source => ({
                  ip: source,
                  loginCount: windowEvents.filter(e => e.sourceIp === source).length
                })),
                targetComputers: Array.from(new Set(windowEvents.map(e => e.computerName).filter(c => c)))
              },
              75,
              {
                activityType: 'rdp_burst',
                detectionMethod: 'time_window_analysis'
              }
            )

            anomalies.push(anomaly)
          }
        }
      })
    }

    return anomalies
  }

  private groupByTimeWindows(events: AuthEvent[], windowMinutes: number): Record<string, AuthEvent[]> {
    const groups: Record<string, AuthEvent[]> = {}

    events.forEach(event => {
      // Handle both Date objects and string timestamps
      const timestamp = event.timestamp instanceof Date
        ? event.timestamp.getTime()
        : new Date(event.timestamp).getTime()

      const windowStart = Math.floor(timestamp / (windowMinutes * 60 * 1000)) * (windowMinutes * 60 * 1000)
      const windowKey = new Date(windowStart).toISOString()

      if (!groups[windowKey]) {
        groups[windowKey] = []
      }
      groups[windowKey].push(event)
    })

    return groups
  }
}
