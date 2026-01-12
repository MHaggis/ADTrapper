import { CorrelationRule } from './CorrelationRule'
import { AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class HostUserAlertCorrelationRule extends CorrelationRule {
  constructor() {
    super(
      'host-user-alert-correlation',
      'Host-User Alert Correlation',
      'Detects when a user on a specific host triggers multiple security alerts, indicating potential compromise',
      'critical',
      60, // 1 hour time window
      {
        minAlerts: 3,
        timeWindowMinutes: 30,
        confidenceThreshold: 0.8,
        maxTimeBetweenAlerts: 15 // minutes
      },
      {
        overview: 'Detects sophisticated attack patterns where a user account on a specific host exhibits multiple suspicious security events, indicating potential account compromise or lateral movement. Analyzes authentication failures, privilege escalation activities, and temporal patterns to identify compromised user sessions.',
        detectionLogic: 'Correlates security events by user@computer combinations within time windows, analyzing patterns such as authentication failures followed by successful logins, privilege escalation operations, account modifications, and rapid sequences of security events. Uses risk scoring to identify potentially compromised user sessions on specific hosts.',
        falsePositives: 'Legitimate administrative activities by authorized users, automated system maintenance operations, legitimate password reset procedures, or normal business activities that involve multiple security events in sequence. May also trigger during legitimate user onboarding or account management activities.',
        mitigation: [
          'Immediately isolate potentially compromised user accounts and hosts',
          'Force password reset for suspected compromised accounts',
          'Review and revoke any unauthorized privilege escalations',
          'Conduct forensic analysis of affected systems and user activities',
          'Implement multi-factor authentication for all privileged accounts',
          'Enable comprehensive security event logging and monitoring',
          'Establish baseline user behavior patterns for anomaly detection',
          'Implement automated response capabilities for detected threats',
          'Conduct security awareness training for users and administrators',
          'Regular security assessments and penetration testing'
        ],
        windowsEvents: ['4624 (Account Logon Success)', '4625 (Account Logon Failure)', '4672 (Special Privileges Assigned)', '4720 (User Account Created)', '4722 (User Account Enabled)', '4724 (Password Reset Attempted)', '4725 (Account Disabled)', '4732 (Member Added to Local Group)', '4733 (Member Removed from Local Group)', '4740 (Account Locked Out)', '4771 (Kerberos Pre-auth Failed)', '4673 (Sensitive Privilege Use)', '4674 (Privileged Object Operation)'],
        exampleQuery: `index=windows EventCode=4625 OR EventCode=4624 OR EventCode=4672 | stats count by TargetUserName, Computer | where count > 5`,
        recommendedThresholds: {
          minAlerts: 3,
          timeWindowMinutes: 30,
          confidenceThreshold: 0.8,
          maxTimeBetweenAlerts: 15
        }
      }
    )
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Group events by user and computer combinations
    const userHostCombinations = new Map<string, AuthEvent[]>()

    events.forEach(event => {
      if (!event.userName || !event.computerName) return

      const key = `${event.userName.toLowerCase()}@${event.computerName.toLowerCase()}`
      if (!userHostCombinations.has(key)) {
        userHostCombinations.set(key, [])
      }
      userHostCombinations.get(key)!.push(event)
    })

    // Analyze each user-host combination for suspicious patterns
    for (const [combinationKey, userEvents] of Array.from(userHostCombinations)) {
      const [userName, computerName] = combinationKey.split('@')

      // Look for authentication failures followed by suspicious activity
      const authFailures = userEvents.filter(e =>
        e.status === 'Failed' &&
        (e.eventId === '4625' || e.eventId === '529' || e.eventId === '530')
      )

      const successfulLogons = userEvents.filter(e =>
        e.status === 'Success' &&
        (e.eventId === '4624' || e.eventId === '528')
      )

      const suspiciousActivity = userEvents.filter(e =>
        e.eventId === '4672' || // Special privileges assigned to new logon
        e.eventId === '4720' || // User account was created
        e.eventId === '4722' || // User account enabled
        e.eventId === '4724' || // Password reset attempted
        e.eventId === '4725' || // Account disabled
        e.eventId === '4732' || // Member added to local group
        e.eventId === '4733' || // Member removed from local group
        e.eventId === '4740' || // Account locked out
        e.eventId === '4771'    // Kerberos pre-authentication failed
      )

      // Calculate risk score based on patterns
      let riskScore = 0
      let riskFactors: string[] = []

      // High number of auth failures
      if (authFailures.length >= 5) {
        riskScore += 0.4
        riskFactors.push(`${authFailures.length} authentication failures`)
      }

      // Successful logon after multiple failures (brute force success)
      if (authFailures.length >= 3 && successfulLogons.length >= 1) {
        const lastFailure = new Date(Math.max(...authFailures.map(e => new Date(e.timestamp).getTime())))
        const firstSuccess = new Date(Math.min(...successfulLogons.map(e => new Date(e.timestamp).getTime())))

        if (firstSuccess > lastFailure) {
          riskScore += 0.3
          riskFactors.push('Successful login after multiple failures')
        }
      }

      // Suspicious privilege escalation activity
      if (suspiciousActivity.length >= 2) {
        riskScore += 0.3
        riskFactors.push(`${suspiciousActivity.length} suspicious privilege operations`)
      }

      // Check for time-based patterns (rapid activity)
      const timeWindow = 10 * 60 * 1000 // 10 minutes
      const recentEvents = userEvents.filter(e =>
        Date.now() - new Date(e.timestamp).getTime() < timeWindow
      )

      if (recentEvents.length >= 10) {
        riskScore += 0.2
        riskFactors.push(`${recentEvents.length} events in 10 minutes`)
      }

      // Generate correlation if risk score is high enough
      if (riskScore >= this.thresholds.confidenceThreshold) {
        const title = `🚨 Potential Account Compromise: ${userName} on ${computerName}`
        const description = `User ${userName} on host ${computerName} shows suspicious behavior patterns that may indicate account compromise. Risk factors: ${riskFactors.join(', ')}.`

        const evidence = {
          userName,
          computerName,
          riskScore,
          riskFactors,
          authFailures: authFailures.length,
          successfulLogons: successfulLogons.length,
          suspiciousActivity: suspiciousActivity.length,
          totalEvents: userEvents.length,
          timeWindow: `${this.timeWindow} minutes`
        }

        const recommendations = [
          `Immediately investigate user ${userName} activity on ${computerName}`,
          'Check for unauthorized privilege escalation',
          'Review recent password changes and account modifications',
          'Consider isolating the host if compromise is confirmed',
          'Enable enhanced logging and monitoring for this user-host combination'
        ]

        // Find the most recent event timestamp for this user-host combination
        const latestEvent = userEvents.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())[0]
        const eventTimestamp = new Date(latestEvent.timestamp)

        anomalies.push(this.createCorrelationAnomaly(
          title,
          description,
          [], // No specific alerts to correlate, this is event-based
          riskScore,
          [
            { type: 'user', id: userName, name: userName },
            { type: 'computer', id: computerName, name: computerName }
          ],
          evidence,
          recommendations,
          eventTimestamp
        ))
      }
    }

    return anomalies
  }
}
