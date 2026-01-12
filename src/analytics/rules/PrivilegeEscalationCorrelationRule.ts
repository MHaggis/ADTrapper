import { CorrelationRule } from './CorrelationRule'
import { AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class PrivilegeEscalationCorrelationRule extends CorrelationRule {
  constructor() {
    super(
      'privilege-escalation-correlation',
      'Privilege Escalation Correlation',
      'Detects patterns of privilege escalation across users and systems',
      'critical',
      90, // 1.5 hour time window
      {
        minAlerts: 2,
        timeWindowMinutes: 45,
        confidenceThreshold: 0.8,
        minPrivilegeEvents: 3
      },
      {
        overview: 'Detects sophisticated privilege escalation attack chains where attackers progressively gain higher levels of access across multiple systems and user accounts. Analyzes privilege-related events, group membership changes, administrative access patterns, and escalation paths to identify multi-stage attacks.',
        detectionLogic: 'Correlates privilege-related security events across time windows, analyzing patterns such as group membership additions, administrative privilege assignments, password resets, account modifications, and cross-system privilege escalation. Uses risk scoring to identify coordinated privilege escalation campaigns.',
        falsePositives: 'Legitimate administrative activities such as user onboarding, role changes, or system administration tasks. May also trigger during legitimate privilege delegation, automated user provisioning, or authorized access management activities. Normal business processes involving multiple privilege operations.',
        mitigation: [
          'Immediately audit and revoke unauthorized privilege escalations',
          'Implement principle of least privilege for all user accounts',
          'Enable comprehensive privilege auditing and monitoring',
          'Establish approval workflows for privilege assignments',
          'Regular review of group memberships and privilege assignments',
          'Implement multi-factor authentication for privileged accounts',
          'Conduct forensic analysis of privilege escalation paths',
          'Implement automated privilege escalation detection and response',
          'Regular security assessments and penetration testing',
          'Enable detailed audit logging for all privilege operations'
        ],
        windowsEvents: ['4672 (Special Privileges Assigned)', '4673 (Sensitive Privilege Use)', '4674 (Privileged Object Operation)', '4728 (Security Group Member Added)', '4729 (Security Group Member Removed)', '4732 (Member Added to Local Group)', '4733 (Member Removed from Local Group)', '4756 (Member Added to Universal Group)', '4757 (Member Removed from Universal Group)', '4720 (User Account Created)', '4722 (User Account Enabled)', '4724 (Password Reset Attempted)', '4740 (Account Locked Out)'],
        exampleQuery: `index=windows EventCode=4672 OR EventCode=4728 OR EventCode=4732 | stats count by TargetUserName | where count > 3`,
        recommendedThresholds: {
          minAlerts: 2,
          timeWindowMinutes: 45,
          confidenceThreshold: 0.8,
          minPrivilegeEvents: 3
        }
      }
    )
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Group events by user
    const userEvents = new Map<string, AuthEvent[]>()

    events.forEach(event => {
      if (!event.userName) return

      const userKey = event.userName.toLowerCase()
      if (!userEvents.has(userKey)) {
        userEvents.set(userKey, [])
      }
      userEvents.get(userKey)!.push(event)
    })

    // Analyze each user's privilege escalation patterns
    for (const [userName, userEventsList] of Array.from(userEvents)) {
      const privilegePatterns = this.analyzePrivilegePatterns(userEventsList)

      if (privilegePatterns.riskScore >= this.thresholds.confidenceThreshold) {
        const title = `🚨 Privilege Escalation Detected: ${userName}`
        const description = `User ${userName} shows ${privilegePatterns.description}. This may indicate unauthorized privilege escalation or compromised administrative access.`

        const evidence = {
          userName,
          riskScore: privilegePatterns.riskScore,
          riskFactors: privilegePatterns.riskFactors,
          privilegeEvents: privilegePatterns.privilegeEvents,
          affectedHosts: privilegePatterns.affectedHosts,
          timeWindow: `${this.timeWindow} minutes`,
          escalationPath: privilegePatterns.escalationPath
        }

        const recommendations = [
          `Immediately review privileges for user ${userName}`,
          'Audit recent group membership changes and privilege assignments',
          'Check for unauthorized administrative access',
          'Review password changes and account modifications',
          'Consider revoking elevated privileges until investigation is complete',
          'Enable detailed audit logging for privilege operations'
        ]

        // Get unique affected hosts
        const affectedEntities: Array<{ type: 'user' | 'computer' | 'ip'; id: string; name: string }> = [
          { type: 'user', id: userName, name: userName }
        ]

        privilegePatterns.affectedHosts.forEach(host => {
          affectedEntities.push({ type: 'computer', id: host, name: host })
        })

        // Find the most recent privilege event timestamp
        const latestEvent = userEventsList.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())[0]
        const eventTimestamp = new Date(latestEvent.timestamp)

        anomalies.push(this.createCorrelationAnomaly(
          title,
          description,
          [], // Event-based correlation
          privilegePatterns.riskScore,
          affectedEntities,
          evidence,
          recommendations,
          eventTimestamp
        ))
      }
    }

    return anomalies
  }

  private analyzePrivilegePatterns(events: AuthEvent[]): {
    riskScore: number
    description: string
    riskFactors: string[]
    privilegeEvents: Array<{
      eventId: string
      timestamp: Date
      computerName?: string
      description: string
    }>
    affectedHosts: Set<string>
    escalationPath: string[]
  } {
    const privilegeEvents: Array<{
      eventId: string
      timestamp: Date
      computerName?: string
      description: string
    }> = []

    const affectedHosts = new Set<string>()
    const riskFactors: string[] = []
    const escalationPath: string[] = []

    let riskScore = 0

    // Sort events by timestamp
    const sortedEvents = events.sort((a, b) =>
      new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    )

    // Analyze privilege-related events
    sortedEvents.forEach(event => {
      if (event.computerName) {
        affectedHosts.add(event.computerName)
      }

      switch (event.eventId) {
        case '4672': // Special privileges assigned to new logon
          privilegeEvents.push({
            eventId: event.eventId,
            timestamp: new Date(event.timestamp),
            computerName: event.computerName,
            description: 'Special privileges assigned to logon'
          })
          escalationPath.push('Elevated privileges granted')
          riskScore += 0.2
          break

        case '4732': // Member added to local group
          privilegeEvents.push({
            eventId: event.eventId,
            timestamp: new Date(event.timestamp),
            computerName: event.computerName,
            description: 'Added to local group'
          })
          escalationPath.push('Added to privileged group')
          riskScore += 0.25
          break

        case '4733': // Member removed from local group
          privilegeEvents.push({
            eventId: event.eventId,
            timestamp: new Date(event.timestamp),
            computerName: event.computerName,
            description: 'Removed from local group'
          })
          escalationPath.push('Removed from privileged group')
          // This could be cleanup after compromise
          riskScore += 0.1
          break

        case '4720': // User account was created
          privilegeEvents.push({
            eventId: event.eventId,
            timestamp: new Date(event.timestamp),
            computerName: event.computerName,
            description: 'User account created'
          })
          escalationPath.push('New account created')
          riskScore += 0.15
          break

        case '4722': // User account enabled
          privilegeEvents.push({
            eventId: event.eventId,
            timestamp: new Date(event.timestamp),
            computerName: event.computerName,
            description: 'User account enabled'
          })
          escalationPath.push('Account enabled')
          riskScore += 0.1
          break

        case '4724': // Password reset attempted
          privilegeEvents.push({
            eventId: event.eventId,
            timestamp: new Date(event.timestamp),
            computerName: event.computerName,
            description: 'Password reset attempted'
          })
          escalationPath.push('Password reset')
          riskScore += 0.15
          break

        case '4756': // Member added to universal group
          privilegeEvents.push({
            eventId: event.eventId,
            timestamp: new Date(event.timestamp),
            computerName: event.computerName,
            description: 'Added to universal group'
          })
          escalationPath.push('Added to universal privileged group')
          riskScore += 0.3
          break

        case '4757': // Member removed from universal group
          privilegeEvents.push({
            eventId: event.eventId,
            timestamp: new Date(event.timestamp),
            computerName: event.computerName,
            description: 'Removed from universal group'
          })
          escalationPath.push('Removed from universal privileged group')
          riskScore += 0.1
          break
      }
    })

    // Analyze patterns and risk factors
    if (privilegeEvents.length >= this.thresholds.minPrivilegeEvents) {
      riskFactors.push(`${privilegeEvents.length} privilege-related events`)
    }

    // Multiple hosts affected
    if (affectedHosts.size >= 2) {
      riskScore += 0.2
      riskFactors.push(`Privilege changes on ${affectedHosts.size} hosts`)
    }

    // Rapid privilege escalation (multiple events in short time)
    if (privilegeEvents.length >= 3) {
      const firstEvent = privilegeEvents[0].timestamp instanceof Date
        ? privilegeEvents[0].timestamp.getTime()
        : new Date(privilegeEvents[0].timestamp).getTime()
      const lastEvent = privilegeEvents[privilegeEvents.length - 1].timestamp instanceof Date
        ? privilegeEvents[privilegeEvents.length - 1].timestamp.getTime()
        : new Date(privilegeEvents[privilegeEvents.length - 1].timestamp).getTime()
      const timeSpan = (lastEvent - firstEvent) / (1000 * 60) // minutes

      if (timeSpan <= 30) {
        riskScore += 0.25
        riskFactors.push('Rapid privilege escalation')
      }
    }

    // Check for suspicious sequences
    if (this.hasSuspiciousSequence(privilegeEvents)) {
      riskScore += 0.2
      riskFactors.push('Suspicious privilege sequence detected')
    }

    // Create description
    let description = `${privilegeEvents.length} privilege-related events`
    if (riskFactors.length > 0) {
      description += ` with patterns: ${riskFactors.join(', ')}`
    }

    return {
      riskScore: Math.min(1, riskScore),
      description,
      riskFactors,
      privilegeEvents,
      affectedHosts,
      escalationPath
    }
  }

  private hasSuspiciousSequence(events: Array<{
    eventId: string
    timestamp: Date
    description: string
  }>): boolean {
    // Look for suspicious patterns like:
    // 1. Account creation followed by privilege escalation
    // 2. Password reset followed by group membership changes
    // 3. Multiple privilege assignments in sequence

    const eventIds = events.map(e => e.eventId)

    // Account creation followed by privilege escalation
    if (eventIds.includes('4720') && (eventIds.includes('4672') || eventIds.includes('4732'))) {
      return true
    }

    // Password reset followed by privilege changes
    if (eventIds.includes('4724') && (eventIds.includes('4672') || eventIds.includes('4732'))) {
      return true
    }

    // Multiple privilege escalations
    const privilegeEvents = eventIds.filter(id => ['4672', '4732', '4756'].includes(id))
    if (privilegeEvents.length >= 3) {
      return true
    }

    return false
  }
}
