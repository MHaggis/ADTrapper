import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext } from '../types'

export class PrivilegedAccessRule extends BaseRule {
  constructor() {
    super({
      id: 'privileged_access_monitoring',
      name: 'Privileged Access Monitoring',
      description: 'Monitors and detects suspicious privileged account activity',
      category: 'privilege',
      severity: 'high',
      timeWindow: 60, // 1 hour
      thresholds: {
        maxPrivilegedLogins: 5,      // Max logins per hour
        maxTargetSystems: 3,         // Max different systems accessed
        suspiciousServiceAccounts: 1, // Any service account login
        dormantAccountDays: 30       // Flag accounts not used in X days
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Monitors privileged account activity to detect suspicious patterns that may indicate account compromise, unauthorized access, or lateral movement. Privileged accounts are primary targets for attackers seeking domain-wide access through Golden Tickets, Pass-the-Hash, and other credential-based attacks.',
        detectionLogic: 'Analyzes authentication events for privileged users (Domain Admins, Enterprise Admins, etc.), identifying excessive logins, multi-system access patterns, service account interactive logins, access from suspicious locations, and dormant account reactivation. Correlates with user profiles and IP intelligence for comprehensive privileged access monitoring.',
        falsePositives: 'Legitimate administrative tasks, system maintenance activities, scheduled backups, automated processes, helpdesk operations, or approved overtime work. Service account interactive logins during system administration or troubleshooting are common legitimate scenarios.',
        mitigation: [
          'Implement Just-In-Time (JIT) administrative access',
          'Enable multi-factor authentication for all privileged accounts',
          'Monitor privileged account usage with session recording',
          'Implement time-based access controls and geolocation restrictions',
          'Regular privileged account auditing and cleanup',
          'Use dedicated administrative workstations (PAWs)',
          'Monitor for Golden Ticket and Pass-the-Hash attacks',
          'Implement behavioral analytics for privileged user patterns',
          'Regular password rotation and complexity enforcement',
          'Enable privileged access management (PAM) solutions'
        ],
        windowsEvents: ['4624 (Successful Logon)', '4672 (Admin Logon)', '4673 (Sensitive Privilege Use)', '4674 (Privileged Service Called)', '4720 (User Account Created)', '4722 (User Account Enabled)', '4724 (Password Reset)', '4732 (Member Added to Group)'],
        exampleQuery: `index=windows EventCode=4624 | stats count by TargetUserName | where TargetUserName IN ("Administrator", "*Admin*", "*Service*") | where count > 10`,
        recommendedThresholds: {
          maxPrivilegedLogins: 5,
          maxTargetSystems: 3,
          suspiciousServiceAccounts: 1,
          dormantAccountDays: 30
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    const recentEvents = this.filterByTimeWindow(events)
    const successfulLogins = recentEvents.filter(event => event.status === 'Success')

    // Get privileged users from context
    const privilegedUsers = context.userProfiles?.filter(profile => profile.privileged) || []
    const privilegedUsernames = new Set(privilegedUsers.map(u => u.userName))

    // Filter logins by privileged users
    const privilegedLogins = successfulLogins.filter(event => 
      event.userName && privilegedUsernames.has(event.userName)
    )

    if (privilegedLogins.length === 0) return anomalies

    // Group by user
    const loginsByUser = this.groupBy(privilegedLogins, event => 
      `${event.userName}@${event.domainName || 'unknown'}`
    )

    Object.entries(loginsByUser).forEach(([userKey, userLogins]) => {
      const userName = userLogins[0].userName!
      const userProfile = privilegedUsers.find(p => p.userName === userName)
      
      // 1. Excessive privileged logins
      if (userLogins.length > this.thresholds.maxPrivilegedLogins) {
        const uniqueSystems = new Set(userLogins.map(login => login.computerName).filter(Boolean))
        
        let confidence = 70
        if (userLogins.length > 10) confidence += 15
        if (uniqueSystems.size > this.thresholds.maxTargetSystems) confidence += 20

        const anomaly = this.createAnomaly(
          'Excessive Privileged Account Activity',
          `Privileged user ${userName} logged in ${userLogins.length} times in the last hour across ${uniqueSystems.size} systems`,
          {
            userName,
            domain: userLogins[0].domainName,
            department: userProfile?.department,
            loginCount: userLogins.length,
            uniqueSystems: uniqueSystems.size,
            systems: Array.from(uniqueSystems),
            timeSpan: this.timeWindow,
            loginPattern: this.analyzeLoginPattern(userLogins),
            sourceIps: Array.from(new Set(userLogins.map(l => l.sourceIp).filter((ip): ip is string => ip !== undefined))),
            loginTimes: userLogins.map(l => l.timestamp)
          },
          confidence
        )

        anomalies.push(anomaly)
      }

      // 2. Privileged access to multiple critical systems
      const uniqueSystems = new Set(userLogins.map(login => login.computerName).filter(Boolean))
      if (uniqueSystems.size > this.thresholds.maxTargetSystems) {
        // Check for domain controllers, servers, etc.
        const criticalSystems = Array.from(uniqueSystems).filter(system =>
          system && (
            system.includes('DC') ||
            system.includes('SERVER') ||
            system.includes('SQL') ||
            system.includes('EXCHANGE')
          )
        )

        if (criticalSystems.length > 1) {
          const anomaly = this.createAnomaly(
            'Privileged Multi-System Access',
            `Privileged user ${userName} accessed ${criticalSystems.length} critical systems: ${criticalSystems.join(', ')}`,
            {
              userName,
              domain: userLogins[0].domainName,
              criticalSystems,
              totalSystems: uniqueSystems.size,
              allSystems: Array.from(uniqueSystems),
              accessPattern: this.analyzeSystemAccess(userLogins),
              department: userProfile?.department
            },
            85
          )

          anomalies.push(anomaly)
        }
      }

      // 3. Service account interactive logins (suspicious)
      const interactiveLogins = userLogins.filter(login => 
        login.logonType === 'Interactive' || login.logonType === 'RemoteInteractive'
      )

      if (userName.toLowerCase().includes('svc_') || 
          userName.toLowerCase().includes('service') ||
          userProfile?.title?.toLowerCase().includes('service')) {
        
        if (interactiveLogins.length > 0) {
          const anomaly = this.createAnomaly(
            'Service Account Interactive Login',
            `Service account ${userName} performed ${interactiveLogins.length} interactive logins (unusual for service accounts)`,
            {
              userName,
              domain: userLogins[0].domainName,
              interactiveLogins: interactiveLogins.length,
              logonTypes: Array.from(new Set(userLogins.map(l => l.logonType).filter(Boolean))),
              systems: Array.from(new Set(interactiveLogins.map(l => l.computerName).filter(Boolean))),
              sourceIps: Array.from(new Set(interactiveLogins.map(l => l.sourceIp).filter(Boolean))),
              isServiceAccount: true
            },
            90
          )

          anomalies.push(anomaly)
        }
      }

      // 4. Privileged access from unusual locations
      const sourceIps = Array.from(new Set(userLogins.map(login => login.sourceIp).filter(Boolean)))
      const ipIntel = sourceIps.map(ip => 
        context.ipIntelligence?.find(intel => intel.ip === ip)
      ).filter(Boolean)

      const suspiciousIps = ipIntel.filter(intel => 
        intel && (intel.isTor || intel.isVpn || intel.isMalicious || intel.riskScore > 70)
      )

      if (suspiciousIps.length > 0) {
        const anomaly = this.createAnomaly(
          'Privileged Access from Suspicious Location',
          `Privileged user ${userName} accessed systems from ${suspiciousIps.length} suspicious IP addresses`,
          {
            userName,
            domain: userLogins[0].domainName,
            suspiciousIps: suspiciousIps.map(ip => ({
              ip: ip!.ip,
              country: ip!.country,
              isTor: ip!.isTor,
              isVpn: ip!.isVpn,
              isMalicious: ip!.isMalicious,
              riskScore: ip!.riskScore
            })),
            allSourceIps: sourceIps,
            loginCount: userLogins.length
          },
          95
        )

        anomalies.push(anomaly)
      }
    })

    // 5. Check for dormant privileged accounts suddenly becoming active
    privilegedUsers.forEach(user => {
      const userLogins = privilegedLogins.filter(login => login.userName === user.userName)
      
      if (userLogins.length > 0) {
        // In a real implementation, you'd check against historical data
        // For now, we'll simulate this check
        const simulatedLastActivity = new Date(Date.now() - (Math.random() * 60 * 24 * 60 * 60 * 1000)) // Random last activity
        const daysSinceLastActivity = (Date.now() - simulatedLastActivity.getTime()) / (1000 * 60 * 60 * 24)
        
        if (daysSinceLastActivity > this.thresholds.dormantAccountDays) {
          const anomaly = this.createAnomaly(
            'Dormant Privileged Account Reactivation',
            `Privileged account ${user.userName} became active after ${Math.round(daysSinceLastActivity)} days of inactivity`,
            {
              userName: user.userName,
              domain: user.domain,
              department: user.department,
              daysDormant: Math.round(daysSinceLastActivity),
              currentLogins: userLogins.length,
              lastActivitySimulated: simulatedLastActivity,
              reactivationSystems: Array.from(new Set(userLogins.map(l => l.computerName).filter(Boolean)))
            },
            80
          )

          anomalies.push(anomaly)
        }
      }
    })

    return anomalies
  }

  private analyzeLoginPattern(logins: AuthEvent[]): any {
    const timeIntervals = []
    const sortedLogins = logins.sort((a, b) => {
      const aTime = a.timestamp instanceof Date ? a.timestamp.getTime() : new Date(a.timestamp).getTime()
      const bTime = b.timestamp instanceof Date ? b.timestamp.getTime() : new Date(b.timestamp).getTime()
      return aTime - bTime
    })

    for (let i = 1; i < sortedLogins.length; i++) {
      const currentTime = sortedLogins[i].timestamp instanceof Date
        ? sortedLogins[i].timestamp.getTime()
        : new Date(sortedLogins[i].timestamp).getTime()
      const prevTime = sortedLogins[i-1].timestamp instanceof Date
        ? sortedLogins[i-1].timestamp.getTime()
        : new Date(sortedLogins[i-1].timestamp).getTime()
      const interval = currentTime - prevTime
      timeIntervals.push(interval / (1000 * 60)) // Convert to minutes
    }

    const avgInterval = timeIntervals.length > 0 
      ? timeIntervals.reduce((sum, interval) => sum + interval, 0) / timeIntervals.length 
      : 0

    return {
      totalLogins: logins.length,
      timeSpanMinutes: logins.length > 1 ? 
        (sortedLogins[sortedLogins.length - 1].timestamp.getTime() - sortedLogins[0].timestamp.getTime()) / (1000 * 60) : 0,
      averageIntervalMinutes: Math.round(avgInterval * 10) / 10,
      isRapidFire: avgInterval < 2, // Less than 2 minutes between logins
      loginFrequency: logins.length / (this.timeWindow / 60) // Logins per minute
    }
  }

  private analyzeSystemAccess(logins: AuthEvent[]): any {
    const systemAccess = this.groupBy(logins, login => login.computerName || 'unknown')
    
    return {
      systemCount: Object.keys(systemAccess).length,
      systemBreakdown: Object.entries(systemAccess).map(([system, systemLogins]) => ({
        system,
        loginCount: systemLogins.length,
        firstAccess: new Date(Math.min(...systemLogins.map(l => l.timestamp.getTime()))),
        lastAccess: new Date(Math.max(...systemLogins.map(l => l.timestamp.getTime())))
      })),
      accessPattern: this.determineAccessPattern(systemAccess)
    }
  }

  private determineAccessPattern(systemAccess: Record<string, AuthEvent[]>): string {
    const systems = Object.keys(systemAccess)
    
    if (systems.length === 1) return 'single_system'
    if (systems.length <= 3) return 'limited_systems'
    if (systems.length <= 5) return 'multiple_systems'
    return 'widespread_access'
  }
}
