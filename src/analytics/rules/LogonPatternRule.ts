import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, RuleConfig } from '../types'

/**
 * Advanced Rule: Logon Pattern Analysis
 * Detects unusual logon patterns and behaviors that may indicate compromise or policy violations
 */
export class LogonPatternRule extends BaseRule {
  constructor(config: RuleConfig = {}) {
    super({
      id: 'logon_patterns',
      name: 'Unusual Logon Patterns',
      description: 'Detects abnormal authentication patterns including impossible travel, concurrent sessions, and unusual timing',
      category: 'behavioral',
      severity: 'medium',
      enabled: true,
      thresholds: {
        impossibleTravelKmH: 800,     // Impossible travel speed in km/h
        concurrentSessionMinutes: 5,   // Minutes between logins to consider concurrent
        maxNormalSessionsPerUser: 3,   // Max normal concurrent sessions
        unusualHourThreshold: 0.1,     // Percentage of normal activity to consider unusual
        ...config.thresholds
      },
      detailedDescription: {
        overview: 'Detects abnormal authentication patterns that may indicate account compromise, unauthorized access, or policy violations. Analyzes user behavior patterns including impossible travel, concurrent sessions from different locations, unusual timing, and privilege escalation attempts.',
        detectionLogic: 'Combines multiple behavioral analysis techniques: (1) Geographic analysis for impossible travel detection using IP geolocation, (2) Session analysis for concurrent logins from different locations, (3) Temporal analysis for unusual timing patterns outside normal business hours, (4) Logon type analysis for unusual access methods, (5) Privilege escalation detection for unauthorized access to sensitive systems.',
        falsePositives: 'Legitimate travel with VPN usage, shared workstations, helpdesk remote assistance, legitimate concurrent access from multiple devices, approved off-hours access, system administration tasks, or temporary privilege elevation for maintenance activities.',
        mitigation: [
          'Implement multi-factor authentication for all accounts',
          'Enable location-based authentication policies',
          'Configure session limits and monitoring',
          'Set up time-based access controls for sensitive operations',
          'Implement behavioral analytics and risk scoring',
          'Use VPN for remote access instead of direct RDP',
          'Regular review of user access patterns and anomalies',
          'Implement just-in-time administrative access',
          'Monitor for impossible travel scenarios',
          'Enable session recording for high-risk activities'
        ],
        windowsEvents: ['4624 (Successful Logon)', '4625 (Failed Logon)', '4648 (Explicit Credential Logon)', '4647 (User Logoff)', '4672 (Admin Logon)', '4778 (Session Reconnect)', '4779 (Session Disconnect)'],
        exampleQuery: `index=windows EventCode=4624 | stats count by TargetUserName, IpAddress | eventstats dc(IpAddress) as ip_count by TargetUserName | where ip_count > 3`,
        recommendedThresholds: {
          impossibleTravelKmH: 800,
          concurrentSessionMinutes: 5,
          maxNormalSessionsPerUser: 3,
          unusualHourThreshold: 0.1
        }
      },
      ...config
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    
    // Group successful logins by user
    const successfulLogins = events
      .filter(e => e.status === 'Success' && e.userName && e.userName !== 'ANONYMOUS LOGON')
      .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
    
    const userLogins = new Map<string, AuthEvent[]>()
    successfulLogins.forEach(event => {
      const userKey = `${event.domainName || 'LOCAL'}\\${event.userName}`
      if (!userLogins.has(userKey)) {
        userLogins.set(userKey, [])
      }
      userLogins.get(userKey)!.push(event)
    })

    // Analyze each user's login patterns
    userLogins.forEach((logins, userKey) => {
      const userName = userKey.split('\\')[1]
      const domain = userKey.split('\\')[0]
      
      // Get user profile
      const userProfile = context.userProfiles?.find(u => 
        u.userName === userName && u.domain === domain
      )
      
      // Check for impossible travel
      const impossibleTravelAnomalies = this.detectImpossibleTravel(logins, userName, userProfile)
      anomalies.push(...impossibleTravelAnomalies)
      
      // Check for concurrent sessions
      const concurrentSessionAnomalies = this.detectConcurrentSessions(logins, userName, userProfile)
      anomalies.push(...concurrentSessionAnomalies)
      
      // Check for unusual timing patterns
      const timingAnomalies = this.detectUnusualTiming(logins, userName, userProfile, context)
      anomalies.push(...timingAnomalies)
      
      // Check for unusual logon types
      const logonTypeAnomalies = this.detectUnusualLogonTypes(logins, userName, userProfile)
      anomalies.push(...logonTypeAnomalies)
    })

    // Check for privilege escalation patterns
    const escalationAnomalies = this.detectPrivilegeEscalation(successfulLogins, context)
    anomalies.push(...escalationAnomalies)

    return anomalies
  }

  private detectImpossibleTravel(logins: AuthEvent[], userName: string, userProfile: any): Anomaly[] {
    const anomalies: Anomaly[] = []
    
    // Group logins by IP with location data
    const loginsWithLocation = logins.filter(login => {
      const geoInfo = this.getGeoInfo(login.sourceIp || null, userProfile)
      return geoInfo && geoInfo.latitude && geoInfo.longitude
    })
    
    for (let i = 1; i < loginsWithLocation.length; i++) {
      const prevLogin = loginsWithLocation[i - 1]
      const currLogin = loginsWithLocation[i]
      
      const prevGeo = this.getGeoInfo(prevLogin.sourceIp || null, userProfile)
      const currGeo = this.getGeoInfo(currLogin.sourceIp || null, userProfile)
      
      if (prevGeo && currGeo && prevLogin.sourceIp !== currLogin.sourceIp) {
        const distance = this.calculateDistance(
          prevGeo.latitude, prevGeo.longitude,
          currGeo.latitude, currGeo.longitude
        )
        
        const timeDiff = new Date(currLogin.timestamp).getTime() - new Date(prevLogin.timestamp).getTime()
        const timeDiffHours = timeDiff / (1000 * 60 * 60)
        const speedKmH = distance / timeDiffHours
        
        if (speedKmH > this.thresholds.impossibleTravelKmH) {
          anomalies.push({
            id: `impossible_travel_${userName}_${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'high' as const,
            confidence: 90,
            timestamp: currLogin.timestamp,
            detectedAt: new Date(),
            title: `Impossible Travel: ${userName}`,
            description: `User ${userName} authenticated from ${currGeo.city}, ${currGeo.country} only ${Math.round(timeDiffHours * 60)} minutes after authenticating from ${prevGeo.city}, ${prevGeo.country}. Required travel speed: ${Math.round(speedKmH)} km/h (${Math.round(distance)} km).`,
            category: 'behavioral' as const,
            evidence: {
              firstLocation: {
                ip: prevLogin.sourceIp,
                city: prevGeo.city,
                country: prevGeo.country,
                timestamp: prevLogin.timestamp,
                computer: prevLogin.computerName
              },
              secondLocation: {
                ip: currLogin.sourceIp,
                city: currGeo.city,
                country: currGeo.country,
                timestamp: currLogin.timestamp,
                computer: currLogin.computerName
              },
              distance: Math.round(distance),
              timeDifference: timeDiffHours,
              requiredSpeed: Math.round(speedKmH),
              impossibilityFactor: speedKmH / this.thresholds.impossibleTravelKmH
            },
            timeWindow: {
              start: prevLogin.timestamp,
              end: currLogin.timestamp
            },
            metadata: {
              rule: 'impossible_travel',
              user: userName,
              domain: prevLogin.domainName,
              department: userProfile?.department,
              privileged: userProfile?.privileged,
            },
            affectedEntities: [
              { type: 'user', id: userName, name: userName },
              { type: 'ip', id: prevLogin.sourceIp!, name: prevLogin.sourceIp! },
              { type: 'ip', id: currLogin.sourceIp!, name: currLogin.sourceIp! }
            ],
            recommendations: [
              'Investigate both login sessions for signs of compromise',
              'Check if user was actually traveling or using VPN',
              'Verify the authenticity of both login attempts',
              'Consider temporarily suspending the account',
              'Review all recent activity from both IP addresses'
            ]
          })
        }
      }
    }
    
    return anomalies
  }

  private detectConcurrentSessions(logins: AuthEvent[], userName: string, userProfile: any): Anomaly[] {
    const anomalies: Anomaly[] = []
    const concurrentThresholdMs = this.thresholds.concurrentSessionMinutes * 60 * 1000
    
    // Find overlapping login sessions
    const activeSessions: Array<{ login: AuthEvent, endTime: Date }> = []
    
    for (const login of logins) {
      const loginTime = new Date(login.timestamp)
      
      // Remove expired sessions (assuming 8-hour session duration if no logoff detected)
      const sessionDurationMs = 8 * 60 * 60 * 1000 // 8 hours
      activeSessions.splice(0, activeSessions.length, ...activeSessions.filter(session => 
        session.endTime.getTime() > loginTime.getTime()
      ))
      
      // Check for concurrent sessions from different IPs
      const concurrentFromDifferentIPs = activeSessions.filter(session => 
        session.login.sourceIp !== login.sourceIp &&
        Math.abs(loginTime.getTime() - new Date(session.login.timestamp).getTime()) < concurrentThresholdMs
      )
      
      if (concurrentFromDifferentIPs.length > 0) {
        anomalies.push({
          id: `concurrent_sessions_${userName}_${loginTime.getTime()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'medium' as const,
          confidence: 80,
          timestamp: login.timestamp,
          detectedAt: new Date(),
          title: `Concurrent Sessions: ${userName}`,
          description: `User ${userName} has concurrent login sessions from different locations. Current login from ${login.sourceIp} while still having active sessions from ${concurrentFromDifferentIPs.map(s => s.login.sourceIp).join(', ')}.`,
          category: 'behavioral' as const,
          evidence: {
            newSession: {
              ip: login.sourceIp,
              computer: login.computerName,
              timestamp: login.timestamp,
              logonType: login.logonType
            },
            concurrentSessions: concurrentFromDifferentIPs.map(session => ({
              ip: session.login.sourceIp,
              computer: session.login.computerName,
              timestamp: session.login.timestamp,
              logonType: session.login.logonType
            })),
            totalConcurrentSessions: concurrentFromDifferentIPs.length + 1
          },
          timeWindow: {
            start: new Date(Math.min(...concurrentFromDifferentIPs.map(s => new Date(s.login.timestamp).getTime()), new Date(login.timestamp).getTime())),
            end: login.timestamp
          },
          metadata: {
            rule: 'concurrent_sessions',
            user: userName,
            domain: login.domainName,
            department: userProfile?.department,
            privileged: userProfile?.privileged,
          },
          affectedEntities: [
            { type: 'user', id: userName, name: userName },
            { type: 'ip', id: login.sourceIp!, name: login.sourceIp! },
            ...concurrentFromDifferentIPs.map(s => ({ type: 'ip' as const, id: s.login.sourceIp!, name: s.login.sourceIp! }))
          ],
          recommendations: [
            'Verify if user is legitimately accessing from multiple locations',
            'Check for shared account usage (policy violation)',
            'Consider if VPN or remote access is expected',
            'Review session activities for signs of compromise',
            'Implement session monitoring and limits'
          ]
        })
      }
      
      // Add current session to active sessions
      activeSessions.push({
        login: login,
        endTime: new Date(loginTime.getTime() + sessionDurationMs)
      })
    }
    
    return anomalies
  }

  private detectUnusualTiming(logins: AuthEvent[], userName: string, userProfile: any, context: AnalyticsContext): Anomaly[] {
    const anomalies: Anomaly[] = []
    
    // Get user's normal hours from profile or calculate from historical data
    const normalHours = userProfile?.normalLoginHours || { start: 8, end: 17 }
    
    // Find logins outside normal hours
    const offHoursLogins = logins.filter(login => {
      const hour = new Date(login.timestamp).getHours()
      return hour < normalHours.start || hour > normalHours.end
    })
    
    if (offHoursLogins.length > 0) {
      // Calculate what percentage of this user's logins are off-hours
      const offHoursPercentage = offHoursLogins.length / logins.length
      
      if (offHoursPercentage > this.thresholds.unusualHourThreshold) {
        anomalies.push({
          id: `unusual_timing_${userName}_${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: userProfile?.privileged ? 'medium' as const : 'low' as const,
          confidence: 70,
          timestamp: offHoursLogins[offHoursLogins.length - 1].timestamp,
          detectedAt: new Date(),
          title: `Off-Hours Activity: ${userName}`,
          description: `User ${userName} has ${offHoursLogins.length} authentication attempts outside normal business hours (${normalHours.start}:00-${normalHours.end}:00), representing ${Math.round(offHoursPercentage * 100)}% of their total activity.`,
          category: 'temporal' as const,
          evidence: {
            normalHours: `${normalHours.start}:00-${normalHours.end}:00`,
            offHoursCount: offHoursLogins.length,
            totalLogins: logins.length,
            offHoursPercentage: Math.round(offHoursPercentage * 100),
            offHoursLogins: offHoursLogins.slice(0, 10).map(login => ({
              timestamp: login.timestamp,
              hour: new Date(login.timestamp).getHours(),
              sourceIP: login.sourceIp,
              computer: login.computerName
            }))
          },
          timeWindow: {
            start: offHoursLogins[0].timestamp,
            end: offHoursLogins[offHoursLogins.length - 1].timestamp
          },
          metadata: {
            rule: 'off_hours_activity',
            user: userName,
            domain: logins[0].domainName,
            department: userProfile?.department,
            privileged: userProfile?.privileged,
          },
          affectedEntities: [
            { type: 'user', id: userName, name: userName }
          ],
          recommendations: [
            'Verify if off-hours access is authorized and necessary',
            'Check if user has legitimate remote work requirements',
            'Review activities performed during off-hours sessions',
            'Consider implementing time-based access controls',
            'Monitor for any unusual activities during these sessions'
          ]
        })
      }
    }
    
    return anomalies
  }

  private detectUnusualLogonTypes(logins: AuthEvent[], userName: string, userProfile: any): Anomaly[] {
    const anomalies: Anomaly[] = []
    
    // Count logon types
    const logonTypeCounts = new Map<string, number>()
    logins.forEach(login => {
      if (login.logonType) {
        logonTypeCounts.set(login.logonType, (logonTypeCounts.get(login.logonType) || 0) + 1)
      }
    })
    
    // Look for unusual patterns
    const hasRemoteDesktop = logonTypeCounts.has('RemoteInteractive')
    const hasNetworkLogon = logonTypeCounts.has('Network')
    const hasInteractiveLogon = logonTypeCounts.has('Interactive')
    
    // Flag if user suddenly starts using RDP when they normally don't
    if (hasRemoteDesktop && !userProfile?.normalLogonTypes?.includes('RemoteInteractive')) {
      const rdpCount = logonTypeCounts.get('RemoteInteractive') || 0
      
      anomalies.push({
        id: `unusual_rdp_${userName}_${Date.now()}`,
        ruleId: this.id,
        ruleName: this.name,
        severity: 'medium' as const,
        confidence: 70,
        timestamp: logins[logins.length - 1].timestamp,
        detectedAt: new Date(),
        title: `Unusual RDP Usage: ${userName}`,
        description: `User ${userName} has ${rdpCount} Remote Desktop (RDP) authentication attempts, which is unusual for their normal access pattern.`,
        category: 'behavioral' as const,
        evidence: {
          rdpAttempts: rdpCount,
          logonTypeBreakdown: Object.fromEntries(logonTypeCounts),
          rdpSources: logins
            .filter(l => l.logonType === 'RemoteInteractive')
            .map(l => ({ ip: l.sourceIp, computer: l.computerName, timestamp: l.timestamp }))
        },
        timeWindow: {
          start: logins[0].timestamp,
          end: logins[logins.length - 1].timestamp
        },
        metadata: {
          rule: 'unusual_rdp_usage',
          user: userName,
          domain: logins[0].domainName,
          department: userProfile?.department,
          privileged: userProfile?.privileged,
        },
        affectedEntities: [
          { type: 'user', id: userName, name: userName }
        ],
        recommendations: [
          'Verify if RDP access is authorized for this user',
          'Check if user has legitimate remote access needs',
          'Review RDP source IPs against known safe locations',
          'Consider implementing RDP gateway or VPN requirements',
          'Monitor RDP sessions for unusual activity'
        ]
      })
    }
    
    return anomalies
  }

  private detectPrivilegeEscalation(logins: AuthEvent[], context: AnalyticsContext): Anomaly[] {
    const anomalies: Anomaly[] = []
    
    // Look for patterns where non-privileged users suddenly access privileged resources
    const privilegedComputers = new Set(['DC01', 'DC02', 'FILESERVER', 'SQLSERVER']) // Could be from context
    
    logins.forEach(login => {
      if (!login.userName || !login.computerName) return
      
      const userProfile = context.userProfiles?.find(u => 
        u.userName === login.userName && u.domain === login.domainName
      )
      
      // Non-privileged user accessing privileged system
      if (!userProfile?.privileged && privilegedComputers.has(login.computerName.toUpperCase())) {
        anomalies.push({
          id: `privilege_escalation_${login.userName}_${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'high' as const,
          confidence: 80,
          timestamp: login.timestamp,
          detectedAt: new Date(),
          title: `Potential Privilege Escalation: ${login.userName}`,
          description: `Non-privileged user ${login.userName} authenticated to privileged system ${login.computerName}.`,
          category: 'privilege' as const,
          evidence: {
            targetComputer: login.computerName,
            sourceIP: login.sourceIp,
            logonType: login.logonType,
            authenticationPackage: login.authenticationPackage
          },
          timeWindow: {
            start: login.timestamp,
            end: login.timestamp
          },
          metadata: {
            rule: 'privilege_escalation',
            user: login.userName,
            domain: login.domainName,
            department: userProfile?.department,
            privileged: userProfile?.privileged,
          },
          affectedEntities: [
            { type: 'user', id: login.userName, name: login.userName },
            { type: 'computer', id: login.computerName, name: login.computerName }
          ],
          recommendations: [
            'Verify if access is authorized through proper change management',
            'Check if user has temporary elevated privileges',
            'Review activities performed on the privileged system',
            'Audit group memberships and permissions',
            'Implement just-in-time access controls'
          ]
        })
      }
    })
    
    return anomalies
  }

  private getGeoInfo(ip: string | null, userProfile: any): any {
    // This would typically integrate with your GeoIP service
    // For now, return mock data based on IP patterns
    if (!ip) return null
    
    // Mock geo data - in real implementation, use actual GeoIP service
    const mockGeoData: { [key: string]: any } = {
      '192.168.1.1': { latitude: 40.7128, longitude: -74.0060, city: 'New York', country: 'USA' },
      '10.0.0.1': { latitude: 40.7128, longitude: -74.0060, city: 'New York', country: 'USA' },
      '203.0.113.1': { latitude: 51.5074, longitude: -0.1278, city: 'London', country: 'UK' }
    }
    
    return mockGeoData[ip] || null
  }

  private calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
    const R = 6371 // Earth's radius in kilometers
    const dLat = this.deg2rad(lat2 - lat1)
    const dLon = this.deg2rad(lon2 - lon1)
    const a = 
      Math.sin(dLat/2) * Math.sin(dLat/2) +
      Math.cos(this.deg2rad(lat1)) * Math.cos(this.deg2rad(lat2)) * 
      Math.sin(dLon/2) * Math.sin(dLon/2)
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a))
    return R * c
  }

  private deg2rad(deg: number): number {
    return deg * (Math.PI/180)
  }
}
