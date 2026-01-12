import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, RuleConfig } from '../types'

/**
 * Advanced Rule: Multiple Authentication Failures
 * Detects patterns of multiple failed authentication attempts indicating potential attacks
 */
export class MultipleFailureRule extends BaseRule {
  constructor(config: RuleConfig = {}) {
    super({
      id: 'multiple_failures',
      name: 'Multiple Authentication Failures',
      description: 'Detects multiple failed authentication attempts that could indicate brute force attacks or account compromise attempts',
      category: 'security',
      severity: 'high',
      enabled: true,
      thresholds: {
        failureCountThreshold: 5,     // Number of failures to trigger alert
        timeWindowMinutes: 30,        // Time window for counting failures
        lockoutThreshold: 10,         // Failures indicating potential lockout attack
        distributedThreshold: 3,      // Failures from different IPs
        ...config.thresholds
      },
      detailedDescription: {
        overview: 'Detects multiple failed authentication attempts that could indicate brute force attacks, account compromise attempts, or distributed password spraying campaigns. Analyzes authentication patterns to identify both single-user and multi-user attack vectors.',
        detectionLogic: 'Groups failed authentication events by user and source IP within configurable time windows. Identifies attack clusters, calculates attempt frequency, and analyzes attack patterns including distributed attacks across multiple users. Escalates severity based on attack characteristics and target account privileges.',
        falsePositives: 'Legitimate password recovery attempts, forgotten passwords, misconfigured applications, shared accounts, or users with multiple legitimate login attempts from different locations/devices.',
        mitigation: [
          'Implement progressive account lockout policies',
          'Enable multi-factor authentication for all accounts',
          'Configure rate limiting on authentication endpoints',
          'Implement CAPTCHA for repeated failures',
          'Monitor for password spraying campaigns',
          'Set up behavioral analytics for authentication patterns',
          'Review and block suspicious IP addresses',
          'Enable account lockout monitoring and alerting'
        ],
        windowsEvents: ['4625 (Failed Logon)', '4624 (Successful Logon)', '4771 (Kerberos Pre-auth Failed)', '4776 (NTLM Authentication)', '4740 (User Account Locked Out)'],
        exampleQuery: `index=windows EventCode=4625 | bucket span=5m _time | stats count by TargetUserName, IpAddress | where count > 5 | sort -count`,
        recommendedThresholds: {
          failureCountThreshold: 5,
          timeWindowMinutes: 30,
          lockoutThreshold: 10,
          distributedThreshold: 3
        }
      },
      ...config
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    
    // Group failed events by user
    const failedEvents = events
      .filter(e => e.status === 'Failed' && e.userName && e.userName !== 'ANONYMOUS LOGON')
      .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
    
    const userFailures = new Map<string, AuthEvent[]>()
    
    for (const event of failedEvents) {
      const userKey = `${event.domainName || 'LOCAL'}\\${event.userName}`
      if (!userFailures.has(userKey)) {
        userFailures.set(userKey, [])
      }
      userFailures.get(userKey)!.push(event)
    }

    // Analyze each user's failed attempts
    userFailures.forEach((failures, userKey) => {
      const userName = userKey.split('\\')[1]
      const domain = userKey.split('\\')[0]
      
      // Find clusters of failures within time windows
      const clusters = this.findFailureClusters(failures)
      
      clusters.forEach(cluster => {
        if (cluster.events.length >= this.thresholds.failureCountThreshold) {
          const uniqueIPs = new Set(cluster.events.map(e => e.sourceIp).filter(ip => ip))
          const uniqueComputers = new Set(cluster.events.map(e => e.computerName).filter(comp => comp))
          
          let severity: 'low' | 'medium' | 'high' | 'critical' = 'medium'
          let confidence = 0.7
          
          // Escalate severity based on patterns
          if (cluster.events.length >= this.thresholds.lockoutThreshold) {
            severity = 'critical'
            confidence = 0.95
          } else if (uniqueIPs.size >= this.thresholds.distributedThreshold) {
            severity = 'high'
            confidence = 0.9
          } else if (cluster.events.length >= this.thresholds.failureCountThreshold * 2) {
            severity = 'high'
            confidence = 0.85
          }
          
          // Get user profile for context
          const userProfile = context.userProfiles?.find(u => 
            u.userName === userName && u.domain === domain
          )
          
          // Check if this account is privileged (escalate severity)
          if (userProfile?.privileged && severity !== 'critical') {
            severity = severity === 'high' ? 'critical' : 'high'
            confidence = Math.min(confidence + 0.1, 1.0)
          }
          
          // Analyze attack patterns
          const attackPattern = this.analyzeAttackPattern(cluster.events)
          
          anomalies.push({
            id: `multiple_failures_${userName}_${cluster.startTime.getTime()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity,
            confidence,
            timestamp: cluster.endTime,
            detectedAt: new Date(),
            title: `Multiple Authentication Failures: ${userName}`,
            description: this.buildFailureDescription(cluster, attackPattern, userProfile),
            category: 'authentication' as const,
            evidence: {
              failureCount: cluster.events.length,
              uniqueSourceIPs: uniqueIPs.size,
              uniqueComputers: uniqueComputers.size,
              sourceIPs: Array.from(uniqueIPs),
              computers: Array.from(uniqueComputers),
              attackPattern: attackPattern,
              failureReasons: this.getFailureReasons(cluster.events),
              logonTypes: Array.from(new Set(cluster.events.map(e => e.logonType).filter(t => t))),
              geographicInformation: Array.from(uniqueIPs).filter((ip): ip is string => !!ip).map(ip => {
                const geoInfo = context.ipIntelligence?.find(ipInfo => ipInfo.ip === ip);
                if (geoInfo) {
                  return {
                    ip,
                    country: geoInfo.country || 'Unknown',
                    city: geoInfo.city || 'Unknown',
                    isVpn: geoInfo.isVpn || false,
                    isTor: geoInfo.isTor || false,
                    riskScore: geoInfo.riskScore || 0
                  };
                } else {
                  const isPrivate = ip.includes('10.') || ip.includes('172.') || ip.includes('192.168.') || ip.includes('127.') || ip.includes('::1') || ip.includes('fe80:');
                  return {
                    ip,
                    country: isPrivate ? 'Local/Private Network' : 'No geographic information available',
                    city: isPrivate ? 'Internal network address' : 'Unknown location',
                    isVpn: false,
                    isTor: false,
                    riskScore: isPrivate ? 0 : 50
                  };
                }
              }),
              events: cluster.events.slice(0, 10).map(e => ({ // Limit to first 10 events
                timestamp: e.timestamp,
                sourceIP: e.sourceIp,
                computer: e.computerName,
                logonType: e.logonType,
                failureReason: e.failureReason
              }))
            },
            timeWindow: {
              start: cluster.startTime,
              end: cluster.endTime
            },
            metadata: {
              rule: 'multiple_failures',
              user: userName,
              domain: domain,
              department: userProfile?.department,
              privileged: userProfile?.privileged,
              durationMinutes: Math.round((cluster.endTime.getTime() - cluster.startTime.getTime()) / 60000)
            },
            affectedEntities: [
              { type: 'user', id: userName, name: userName },
              ...Array.from(uniqueComputers).filter(comp => comp).map(comp => ({ type: 'computer' as const, id: comp!, name: comp! })),
              ...Array.from(uniqueIPs).filter(ip => ip).map(ip => ({ type: 'ip' as const, id: ip!, name: ip! }))
            ],
            recommendations: this.getFailureRecommendations(cluster, attackPattern, userProfile)
          })
        }
      })
    })

    // Look for distributed attacks across multiple users
    const distributedAttacks = this.findDistributedAttacks(failedEvents)
    distributedAttacks.forEach(attack => {
      anomalies.push({
        id: `distributed_attack_${attack.sourceIP}_${Date.now()}`,
        ruleId: this.id,
        ruleName: this.name,
        severity: 'critical' as const,
        confidence: 90,
        timestamp: attack.lastAttempt,
        detectedAt: new Date(),
        title: `Distributed Brute Force Attack from ${attack.sourceIP}`,
        description: `IP address ${attack.sourceIP} attempted to authenticate as ${attack.targetUsers.size} different users with ${attack.events.length} failed attempts over ${Math.round((attack.lastAttempt.getTime() - attack.firstAttempt.getTime()) / 60000)} minutes.`,
        category: 'security' as const,
        evidence: {
          sourceIP: attack.sourceIP,
          targetUsers: Array.from(attack.targetUsers),
          totalAttempts: attack.events.length,
          uniqueTargets: attack.targetUsers.size,
          computers: Array.from(new Set(attack.events.map(e => e.computerName).filter(c => c))),
          attackRate: Math.round(attack.events.length / ((attack.lastAttempt.getTime() - attack.firstAttempt.getTime()) / 60000)),
          geographicInformation: (() => {
            const geoInfo = context.ipIntelligence?.find(ipInfo => ipInfo.ip === attack.sourceIP);
            if (geoInfo) {
              return [{
                ip: attack.sourceIP,
                country: geoInfo.country || 'Unknown',
                city: geoInfo.city || 'Unknown',
                isVpn: geoInfo.isVpn || false,
                isTor: geoInfo.isTor || false,
                riskScore: geoInfo.riskScore || 0
              }];
            } else {
              // Handle private IPs
              const isPrivate = attack.sourceIP.includes('10.') || attack.sourceIP.includes('172.') || attack.sourceIP.includes('192.168.') || attack.sourceIP.includes('127.') || attack.sourceIP.includes('::1') || attack.sourceIP.includes('fe80:');
              return [{
                ip: attack.sourceIP,
                country: isPrivate ? 'Local/Private Network' : 'No geographic information available',
                city: isPrivate ? 'Internal network address' : 'Unknown location',
                isVpn: false,
                isTor: false,
                riskScore: isPrivate ? 0 : 50
              }];
            }
          })()
        },
        timeWindow: {
          start: attack.firstAttempt,
          end: attack.lastAttempt
        },
        metadata: {
          rule: 'distributed_attack',
          durationMinutes: Math.round((attack.lastAttempt.getTime() - attack.firstAttempt.getTime()) / 60000)
        },
        affectedEntities: [
          { type: 'ip', id: attack.sourceIP, name: attack.sourceIP },
          ...Array.from(attack.targetUsers).map(user => ({ type: 'user' as const, id: user, name: user }))
        ],
        recommendations: [
          `Immediately block IP address ${attack.sourceIP}`,
          'Review all target accounts for potential compromise',
          'Check for any successful logins from this IP',
          'Implement rate limiting on authentication endpoints',
          'Consider IP reputation checking'
        ]
      })
    })

    return anomalies
  }

  private findFailureClusters(failures: AuthEvent[]): Array<{
    events: AuthEvent[]
    startTime: Date
    endTime: Date
  }> {
    const clusters: Array<{ events: AuthEvent[], startTime: Date, endTime: Date }> = []
    const timeWindowMs = this.thresholds.timeWindowMinutes * 60 * 1000
    
    for (let i = 0; i < failures.length; i++) {
      const windowStart = new Date(failures[i].timestamp)
      const windowEnd = new Date(windowStart.getTime() + timeWindowMs)
      
      const clusterEvents = failures.filter(event => {
        const eventTime = new Date(event.timestamp)
        return eventTime >= windowStart && eventTime <= windowEnd
      })
      
      if (clusterEvents.length >= this.thresholds.failureCountThreshold) {
        const actualEnd = new Date(Math.max(...clusterEvents.map(e => new Date(e.timestamp).getTime())))
        clusters.push({
          events: clusterEvents,
          startTime: windowStart,
          endTime: actualEnd
        })
        
        // Skip ahead to avoid overlapping clusters
        i += clusterEvents.length - 1
      }
    }
    
    return clusters
  }

  private analyzeAttackPattern(events: AuthEvent[]): {
    type: string
    characteristics: string[]
    riskLevel: 'low' | 'medium' | 'high'
  } {
    const uniqueIPs = new Set(events.map(e => e.sourceIp).filter(ip => ip))
    const uniqueComputers = new Set(events.map(e => e.computerName).filter(comp => comp))
    const logonTypes = new Set(events.map(e => e.logonType).filter(t => t))
    
    const characteristics: string[] = []
    let type = 'Brute Force'
    let riskLevel: 'low' | 'medium' | 'high' = 'medium'
    
    if (uniqueIPs.size === 1) {
      type = 'Concentrated Attack'
      characteristics.push('Single source IP')
    } else {
      type = 'Distributed Attack'
      characteristics.push(`${uniqueIPs.size} different source IPs`)
      riskLevel = 'high'
    }
    
    if (uniqueComputers.size === 1) {
      characteristics.push('Single target computer')
    } else {
      characteristics.push(`${uniqueComputers.size} different computers`)
    }
    
    if (logonTypes.has('RemoteInteractive')) {
      characteristics.push('RDP access attempts')
      riskLevel = 'high'
    }
    
    if (logonTypes.has('Network')) {
      characteristics.push('Network service authentication')
    }
    
    // Check time pattern
    const times = events.map(e => new Date(e.timestamp).getTime())
    const intervals = []
    for (let i = 1; i < times.length; i++) {
      intervals.push(times[i] - times[i-1])
    }
    
    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length
    if (avgInterval < 5000) { // Less than 5 seconds between attempts
      characteristics.push('Rapid-fire attempts (automated)')
      riskLevel = 'high'
    } else if (avgInterval < 60000) { // Less than 1 minute
      characteristics.push('Fast attempts (likely automated)')
    }
    
    return { type, characteristics, riskLevel }
  }

  private buildFailureDescription(cluster: any, attackPattern: any, userProfile: any): string {
    let description = `User ${userProfile?.userName || 'unknown'} experienced ${cluster.events.length} failed authentication attempts `
    description += `over ${Math.round((cluster.endTime.getTime() - cluster.startTime.getTime()) / 60000)} minutes. `
    
    description += `Attack pattern: ${attackPattern.type} - ${attackPattern.characteristics.join(', ')}. `
    
    if (userProfile?.privileged) {
      description += '⚠️ This is a privileged account - potential targeted attack. '
    }
    
    return description
  }

  private getFailureReasons(events: AuthEvent[]): { [reason: string]: number } {
    const reasons: { [reason: string]: number } = {}
    events.forEach(event => {
      const reason = event.failureReason || 'Unknown'
      reasons[reason] = (reasons[reason] || 0) + 1
    })
    return reasons
  }

  private getFailureRecommendations(cluster: any, attackPattern: any, userProfile: any): string[] {
    const recommendations: string[] = []
    
    if (attackPattern.riskLevel === 'high') {
      recommendations.push('URGENT: Investigate immediately - high-risk attack pattern detected')
    }
    
    if (userProfile?.privileged) {
      recommendations.push('Privileged account targeted - implement additional monitoring')
      recommendations.push('Consider temporarily disabling account if compromise suspected')
    }
    
    if (cluster.events.length >= this.thresholds.lockoutThreshold) {
      recommendations.push('Account may be locked - verify user status and unlock if legitimate')
    }
    
    recommendations.push('Review source IPs against threat intelligence feeds')
    recommendations.push('Check for any successful logins from same sources')
    recommendations.push('Consider implementing account lockout policies')
    
    if (attackPattern.characteristics.includes('automated')) {
      recommendations.push('Implement CAPTCHA or rate limiting on login endpoints')
    }
    
    return recommendations
  }

  private findDistributedAttacks(failedEvents: AuthEvent[]): Array<{
    sourceIP: string
    events: AuthEvent[]
    targetUsers: Set<string>
    firstAttempt: Date
    lastAttempt: Date
  }> {
    const ipAttacks = new Map<string, AuthEvent[]>()
    
    // Group by source IP
    failedEvents.forEach(event => {
      if (event.sourceIp) {
        if (!ipAttacks.has(event.sourceIp)) {
          ipAttacks.set(event.sourceIp, [])
        }
        ipAttacks.get(event.sourceIp)!.push(event)
      }
    })
    
    const distributedAttacks: Array<{
      sourceIP: string
      events: AuthEvent[]
      targetUsers: Set<string>
      firstAttempt: Date
      lastAttempt: Date
    }> = []
    
    ipAttacks.forEach((events, sourceIP) => {
      const targetUsers = new Set(events.map(e => e.userName).filter((u): u is string => u !== undefined))
      
      // Consider it distributed if targeting 3+ users with 10+ attempts
      if (targetUsers.size >= 3 && events.length >= 10) {
        const times = events.map(e => new Date(e.timestamp)).sort((a, b) => a.getTime() - b.getTime())
        
        distributedAttacks.push({
          sourceIP,
          events,
          targetUsers,
          firstAttempt: times[0],
          lastAttempt: times[times.length - 1]
        })
      }
    })
    
    return distributedAttacks
  }
}
