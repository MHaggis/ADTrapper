import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, RuleConfig } from '../types'

/**
 * Informational Rule: Password Change Detection
 * Detects and reports password change activities
 */
export class PasswordChangeRule extends BaseRule {
  constructor(config: RuleConfig = {}) {
    super({
      id: 'password_changes',
      name: 'Password Change Activity',
      description: 'Detects password changes and account management activities',
      category: 'informational',
      severity: 'info',
      enabled: true,
      timeWindow: 60, // 1 hour window
      thresholds: {
        failedToSuccessGapMin: 1,
        failedToSuccessGapMax: 60
      },
      detailedDescription: {
        overview: 'Detects password change and reset activities by analyzing authentication patterns. Identifies scenarios where users experience failed logins followed by successful authentication, which typically indicates password changes, resets, or credential updates.',
        detectionLogic: 'Analyzes authentication event sequences looking for failed login attempts followed by successful logins within configurable time windows. Also detects rapid authentication activity patterns that may indicate password reset or change scenarios. Correlates with user profiles to assess context and risk.',
        falsePositives: 'Legitimate password changes, forgotten password scenarios, system maintenance activities, application credential updates, or users with multiple authentication attempts due to memory issues.',
        mitigation: [
          'Establish baseline password change frequencies for users',
          'Implement self-service password reset portals',
          'Monitor for unusual password change patterns',
          'Verify password changes with multi-factor authentication',
          'Regular review of password policies and complexity requirements',
          'Implement password change monitoring and alerting',
          'Use password change events for compliance reporting',
          'Monitor for password change attempts from suspicious locations'
        ],
        windowsEvents: ['4723 (Password Change)', '4724 (Password Reset)', '4625 (Failed Logon)', '4624 (Successful Logon)', '4738 (User Changed)', '4742 (Computer Account Changed)'],
        exampleQuery: `index=windows EventCode=4723 OR EventCode=4724 | stats count by TargetUserName | where count > 1`,
        recommendedThresholds: {
          failedToSuccessGapMin: 1,
          failedToSuccessGapMax: 60
        }
      },
      ...config
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    
    // Sort events by timestamp
    const sortedEvents = [...events].sort((a, b) => 
      new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    )
    
    // Look for failed login followed by successful login pattern
    for (let i = 0; i < sortedEvents.length - 1; i++) {
      const currentEvent = sortedEvents[i]
      const nextEvent = sortedEvents[i + 1]
      
      // Skip if different users
      if (currentEvent.userName !== nextEvent.userName) continue
      
      // Look for failed login followed by successful login
      if (currentEvent.status === 'Failed' && nextEvent.status === 'Success') {
        const timeDiff = new Date(nextEvent.timestamp).getTime() - new Date(currentEvent.timestamp).getTime()
        const timeDiffMinutes = timeDiff / (1000 * 60)
        
        // If there's a gap of 1-60 minutes between failed and successful login, might indicate password change
        if (timeDiffMinutes >= this.thresholds.failedToSuccessGapMin && 
            timeDiffMinutes <= this.thresholds.failedToSuccessGapMax) {
          
          const userProfile = context.userProfiles?.find(u => 
            u.userName === currentEvent.userName && u.domain === currentEvent.domainName
          )
          
          anomalies.push({
            id: `potential_password_change_${currentEvent.userName}_${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'info' as const,
            confidence: 60,
            timestamp: nextEvent.timestamp,
            detectedAt: new Date(),
            title: `Potential Password Change: ${currentEvent.userName}`,
            description: `User ${currentEvent.userName} had a failed login followed by successful login after ${Math.round(timeDiffMinutes)} minutes, suggesting possible password change or reset.`,
            category: 'informational' as const,
            evidence: {
              failedAttemptTime: currentEvent.timestamp,
              successfulLoginTime: nextEvent.timestamp,
              timeGapMinutes: Math.round(timeDiffMinutes),
              sourceIP: nextEvent.sourceIp,
              computer: nextEvent.computerName,
              logonType: nextEvent.logonType,
              failureReason: currentEvent.failureReason
            },
            timeWindow: {
              start: currentEvent.timestamp,
              end: nextEvent.timestamp
            },
            metadata: {
              rule: 'password_change',
              user: currentEvent.userName,
              domain: currentEvent.domainName,
              department: userProfile?.department,
              privileged: userProfile?.privileged
            },
            affectedEntities: [
              { type: 'user' as const, id: currentEvent.userName!, name: currentEvent.userName! }
            ],
            recommendations: [
              'Verify if this was a planned password change',
              'Check if user contacted helpdesk for password reset',
              'Monitor for additional failed attempts from other IPs',
              'Confirm user identity if this was unexpected'
            ]
          })
        }
      }
    }
    
    // Look for rapid account activity patterns that might indicate password changes
    const userActivity = this.groupByUser(sortedEvents)
    
    for (const [userKey, userEvents] of Array.from(userActivity.entries())) {
      const [domain, userName] = userKey.split('\\')
      
      if (userEvents.length < 3) continue
      
      const userProfile = context.userProfiles?.find(u => 
        u.userName === userName && u.domain === domain
      )
      
      // Look for rapid successful logins after failures (might indicate password was changed)
      const rapidActivity = this.findRapidActivityAfterFailures(userEvents)
      
      if (rapidActivity.length > 0) {
        const firstEvent = rapidActivity[0]
        const lastEvent = rapidActivity[rapidActivity.length - 1]
        
        anomalies.push({
          id: `rapid_activity_after_failures_${userName}_${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'info' as const,
          confidence: 70,
          timestamp: lastEvent.timestamp,
          detectedAt: new Date(),
          title: `Rapid Activity After Failures: ${userName}`,
          description: `User ${userName} had ${rapidActivity.length} authentication events in a short time after failures, suggesting password change or reset activity.`,
          category: 'informational' as const,
          evidence: {
            totalEvents: rapidActivity.length,
            timeSpan: Math.round((new Date(lastEvent.timestamp).getTime() - new Date(firstEvent.timestamp).getTime()) / (1000 * 60)),
            eventTypes: rapidActivity.map(e => e.status),
            sourceIPs: Array.from(new Set(rapidActivity.map(e => e.sourceIp).filter((ip): ip is string => ip !== undefined))),
            computers: Array.from(new Set(rapidActivity.map(e => e.computerName).filter((c): c is string => c !== undefined)))
          },
          timeWindow: {
            start: new Date(firstEvent.timestamp),
            end: new Date(lastEvent.timestamp)
          },
          metadata: {
            rule: 'rapid_activity_after_failures',
            user: userName,
            domain: domain,
            department: userProfile?.department,
            privileged: userProfile?.privileged
          },
          affectedEntities: [
            { type: 'user' as const, id: userName, name: userName }
          ],
          recommendations: [
            'Verify if recent password change or reset occurred',
            'Check if user reported authentication issues',
            'Review if this activity pattern is normal for this user',
            'Monitor for any unauthorized access'
          ]
        })
      }
    }

    return anomalies
  }

  private groupByUser(events: AuthEvent[]): Map<string, AuthEvent[]> {
    const userGroups = new Map<string, AuthEvent[]>()
    
    for (const event of events) {
      if (!event.userName) continue
      
      const key = `${event.domainName || 'LOCAL'}\\${event.userName}`
      
      if (!userGroups.has(key)) {
        userGroups.set(key, [])
      }
      
      userGroups.get(key)!.push(event)
    }
    
    return userGroups
  }

  private findRapidActivityAfterFailures(events: AuthEvent[]): AuthEvent[] {
    const rapidActivities: AuthEvent[] = []
    
    // Sort by timestamp
    const sorted = [...events].sort((a, b) => 
      new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    )
    
    let lastFailureTime: Date | null = null
    
    for (const event of sorted) {
      const eventTime = new Date(event.timestamp)
      
      if (event.status === 'Failed') {
        lastFailureTime = eventTime
        continue
      }
      
      // If we have a recent failure and this is within 10 minutes
      if (lastFailureTime && event.status === 'Success') {
        const timeDiff = eventTime.getTime() - lastFailureTime.getTime()
        const minutes = timeDiff / (1000 * 60)
        
        if (minutes <= 10) {
          rapidActivities.push(event)
        }
      }
    }
    
    return rapidActivities
  }

  validate(): { valid: boolean; errors: string[] } {
    const errors: string[] = []
    
    if (!this.thresholds.failedToSuccessGapMin || this.thresholds.failedToSuccessGapMin < 1) {
      errors.push('failedToSuccessGapMin must be at least 1 minute')
    }
    
    if (!this.thresholds.failedToSuccessGapMax || this.thresholds.failedToSuccessGapMax > 120) {
      errors.push('failedToSuccessGapMax should not exceed 120 minutes')
    }
    
    return {
      valid: errors.length === 0,
      errors
    }
  }

  getMetadata() {
    return {
      ...super.getMetadata(),
      purpose: 'Detect password change and reset activities',
      dataRequirements: ['Failed and successful authentication events'],
      detectsPatterns: [
        'Failed login followed by successful login',
        'Rapid authentication activity after failures'
      ],
      falsePositiveRisk: 'Medium - legitimate password changes will trigger this rule',
      investigationSteps: [
        'Verify with user if password was recently changed',
        'Check help desk tickets for password reset requests',
        'Review source IPs for legitimacy',
        'Confirm no unauthorized access occurred'
      ]
    }
  }
}