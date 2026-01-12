import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, RuleConfig } from '../types'

/**
 * Informational Rule: User Authentication Activity
 * Tracks and reports normal user authentication patterns
 */
export class UserActivityRule extends BaseRule {
  constructor(config: RuleConfig = {}) {
    super({
      id: 'user_activity',
      name: 'User Authentication Activity',
      description: 'Tracks user authentication patterns and provides insights into login behavior',
      category: 'informational',
      severity: 'info',
      enabled: true,
      detailedDescription: {
        overview: 'Tracks and analyzes user authentication patterns to establish baseline behavior and provide insights into login activities. This informational rule helps understand normal user access patterns, success rates, and authentication methods used across the environment.',
        detectionLogic: 'Aggregates all authentication events by user, calculating success rates, login frequency, geographic distribution, device usage patterns, and temporal patterns. Analyzes logon types, source IP diversity, and computer access patterns to build comprehensive user activity profiles.',
        falsePositives: 'This is an informational rule designed to report normal activity patterns. It does not generate security alerts but provides baseline data for other security rules and compliance reporting.',
        mitigation: [
          'Use this data to establish normal user behavior baselines',
          'Monitor for deviations from established patterns using other security rules',
          'Review privileged account access patterns for policy compliance',
          'Identify users with unusually high authentication volumes',
          'Analyze geographic access patterns for remote work policies',
          'Track authentication method diversity for security awareness',
          'Use as baseline for detecting account compromise indicators',
          'Support compliance reporting for access pattern analysis'
        ],
        windowsEvents: ['4624 (Successful Logon)', '4625 (Failed Logon)', '4647 (User Logoff)', '4648 (Explicit Credential Logon)', '4672 (Admin Logon)', '4778 (Session Reconnect)', '4779 (Session Disconnect)'],
        exampleQuery: `index=windows EventCode=4624 | stats count by TargetUserName, date_mday | eventstats avg(count) as avg by TargetUserName | eval deviation = abs(count - avg)`,
        recommendedThresholds: {}
      },
      ...config
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    
    // Group events by user
    const userActivity = new Map<string, {
      totalLogins: number
      successfulLogins: number
      failedLogins: number
      firstLogin: Date
      lastLogin: Date
      logonTypes: Set<string>
      sourceIPs: Set<string>
      computers: Set<string>
      hourPattern: number[]
    }>()

    // Process all authentication events
    for (const event of events) {
      if (!event.userName || event.userName === 'ANONYMOUS LOGON') continue
      
      const userKey = `${event.domainName || 'LOCAL'}\\${event.userName}`
      const eventTime = new Date(event.timestamp)
      
      if (!userActivity.has(userKey)) {
        userActivity.set(userKey, {
          totalLogins: 0,
          successfulLogins: 0,
          failedLogins: 0,
          firstLogin: eventTime,
          lastLogin: eventTime,
          logonTypes: new Set(),
          sourceIPs: new Set(),
          computers: new Set(),
          hourPattern: new Array(24).fill(0)
        })
      }
      
      const activity = userActivity.get(userKey)!
      activity.totalLogins++
      
      if (event.status === 'Success') {
        activity.successfulLogins++
      } else if (event.status === 'Failed') {
        activity.failedLogins++
      }
      
      // Update time range
      if (eventTime < activity.firstLogin) activity.firstLogin = eventTime
      if (eventTime > activity.lastLogin) activity.lastLogin = eventTime
      
      // Track patterns
      if (event.logonType) activity.logonTypes.add(event.logonType)
      if (event.sourceIp) activity.sourceIPs.add(event.sourceIp)
      if (event.computerName) activity.computers.add(event.computerName)
      
      // Hour pattern
      activity.hourPattern[eventTime.getHours()]++
    }

    // Generate insights for each user
    userActivity.forEach((activity, userKey) => {
      const userName = userKey.split('\\')[1]
      const domain = userKey.split('\\')[0]
      
      // Success rate calculation
      const successRate = activity.totalLogins > 0 
        ? Math.round((activity.successfulLogins / activity.totalLogins) * 100) 
        : 0
      
      // Most active hour
      const mostActiveHour = activity.hourPattern.indexOf(Math.max(...activity.hourPattern))
      
      // User profile from context
      const userProfile = context.userProfiles?.find(u => 
        u.userName === userName && u.domain === domain
      )
      
      anomalies.push({
        id: `user_activity_${userName}_${Date.now()}`,
        ruleId: this.id,
        ruleName: this.name,
        severity: 'info' as const,
        confidence: 100,
        timestamp: activity.lastLogin,
        detectedAt: new Date(),
        title: `Authentication Summary: ${userName}`,
        description: this.buildUserSummary(activity, userProfile),
        category: 'informational' as const,
        evidence: {
          totalAuthentications: activity.totalLogins,
          successfulLogins: activity.successfulLogins,
          failedAttempts: activity.failedLogins,
          successRate: successRate,
          uniqueIPs: activity.sourceIPs.size,
          uniqueComputers: activity.computers.size,
          logonTypes: Array.from(activity.logonTypes),
          mostActiveHour: mostActiveHour,
          hourlyPattern: activity.hourPattern
        },
        timeWindow: {
          start: activity.firstLogin,
          end: activity.lastLogin
        },
        metadata: {
          rule: 'user_activity',
          user: userName,
          domain: domain,
          department: userProfile?.department,
          privileged: userProfile?.privileged,
          durationHours: Math.round((activity.lastLogin.getTime() - activity.firstLogin.getTime()) / (1000 * 60 * 60))
        },
        affectedEntities: [
          { type: 'user' as const, id: userName, name: userName },
          ...Array.from(activity.computers).map(comp => ({ type: 'computer' as const, id: comp, name: comp })),
          ...Array.from(activity.sourceIPs).map(ip => ({ type: 'ip' as const, id: ip, name: ip }))
        ],
        recommendations: this.getUserRecommendations(activity, userProfile)
      })
    })

    return anomalies
  }

  private buildUserSummary(activity: any, userProfile: any): string {
    const successRate = activity.totalLogins > 0 
      ? Math.round((activity.successfulLogins / activity.totalLogins) * 100) 
      : 0
    
    let summary = `User completed ${activity.totalLogins} authentication attempts with ${successRate}% success rate. `
    
    if (userProfile?.privileged) {
      summary += `⚠️ Privileged account with ${userProfile.department || 'Unknown'} department access. `
    }
    
    if (activity.sourceIPs.size > 1) {
      summary += `Authenticated from ${activity.sourceIPs.size} different IP addresses. `
    }
    
    if (activity.logonTypes.size > 1) {
      summary += `Used multiple authentication methods: ${Array.from(activity.logonTypes).join(', ')}. `
    }
    
    return summary
  }

  private getUserRecommendations(activity: any, userProfile: any): string[] {
    const recommendations: string[] = []
    
    if (activity.failedLogins > 0) {
      recommendations.push(`User had ${activity.failedLogins} failed attempts - consider password policy review`)
    }
    
    if (activity.sourceIPs.size > 3) {
      recommendations.push('Multiple IP addresses detected - verify if user travels or works remotely')
    }
    
    if (userProfile?.privileged && activity.sourceIPs.size > 1) {
      recommendations.push('Privileged account accessing from multiple IPs - implement IP restrictions')
    }
    
    if (activity.logonTypes.has('Network') && activity.logonTypes.has('Interactive')) {
      recommendations.push('Mixed logon types suggest normal desktop and server access patterns')
    }
    
    return recommendations
  }
}
