import { CorrelationRule } from './CorrelationRule'
import { AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class IpAlertPatternRule extends CorrelationRule {
  constructor() {
    super(
      'ip-alert-pattern-correlation',
      'IP Alert Pattern Correlation',
      'Detects suspicious IP addresses that trigger multiple alerts across different users/hosts',
      'high',
      120, // 2 hour time window
      {
        minAlerts: 5,
        timeWindowMinutes: 60,
        confidenceThreshold: 0.7,
        minUniqueUsers: 3,
        minUniqueHosts: 2
      },
      {
        overview: 'Detects suspicious IP addresses that trigger multiple security alerts across different users and hosts. This correlation rule identifies coordinated attacks, scanning campaigns, command and control servers, and compromised systems by analyzing authentication patterns from single source IPs.',
        detectionLogic: 'Correlates authentication events by source IP address, analyzing patterns such as multi-user targeting, multi-host scanning, high failure rates, successful logons after failures, privilege escalation activity, and account lockout patterns. Calculates risk scores based on behavioral patterns and attack characteristics.',
        falsePositives: 'Legitimate administrative tools, monitoring systems, shared workstations, helpdesk operations, or automated processes accessing multiple systems. May also trigger during legitimate bulk operations or system administration tasks.',
        mitigation: [
          'Implement IP-based rate limiting and blocking',
          'Enable geolocation-based access controls',
          'Monitor suspicious IP addresses with threat intelligence',
          'Configure network segmentation to limit lateral movement',
          'Implement behavioral analytics for IP reputation',
          'Use VPN and proxy detection mechanisms',
          'Enable automated IP blocking for high-risk sources',
          'Implement session monitoring and recording',
          'Regular threat intelligence feed updates',
          'Use conditional access policies based on IP risk'
        ],
        windowsEvents: ['4624 (Successful Logon)', '4625 (Failed Logon)', '4672 (Admin Logon)', '4732 (Member Added to Group)', '4740 (User Account Locked Out)', '4768 (Kerberos TGT Requested)', '4771 (Kerberos Pre-auth Failed)'],
        exampleQuery: `index=windows EventCode=4625 | stats count by IpAddress, TargetUserName | stats sum(count) as total_attempts, dc(TargetUserName) as unique_users by IpAddress | where total_attempts > 20 AND unique_users > 3`,
        recommendedThresholds: {
          minAlerts: 5,
          timeWindowMinutes: 60,
          confidenceThreshold: 0.7,
          minUniqueUsers: 3,
          minUniqueHosts: 2
        }
      }
    )
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Group events by source IP
    const ipEvents = new Map<string, AuthEvent[]>()

    events.forEach(event => {
      if (!event.sourceIp) return

      if (!ipEvents.has(event.sourceIp)) {
        ipEvents.set(event.sourceIp, [])
      }
      ipEvents.get(event.sourceIp)!.push(event)
    })

    // Analyze each IP's behavior patterns
    for (const [ip, ipEventsList] of Array.from(ipEvents)) {
      if (ipEventsList.length < this.thresholds.minAlerts) continue

      // Analyze patterns for this IP
      const patterns = this.analyzeIpPatterns(ipEventsList)

      if (patterns.riskScore >= this.thresholds.confidenceThreshold) {
        const title = `🌐 Suspicious IP Activity: ${ip}`
        const description = `IP address ${ip} shows ${patterns.description}. This may indicate coordinated attacks, scanning, or compromised systems.`

        const evidence = {
          ipAddress: ip,
          riskScore: patterns.riskScore,
          riskFactors: patterns.riskFactors,
          totalEvents: ipEventsList.length,
          uniqueUsers: patterns.uniqueUsers.size,
          uniqueHosts: patterns.uniqueHosts.size,
          failedLogons: patterns.failedLogons,
          successfulLogons: patterns.successfulLogons,
          timeWindow: `${this.timeWindow} minutes`,
          patterns: patterns.patterns
        }

        const recommendations = [
          `Block or monitor IP ${ip} for suspicious activity`,
          'Review all authentication attempts from this IP',
          'Check for brute force patterns across multiple accounts',
          'Consider geo-blocking if IP is from high-risk location',
          'Enable rate limiting for authentication from this IP'
        ]

        // Find the most recent event timestamp for this IP
        const latestEvent = ipEventsList.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())[0]
        const eventTimestamp = new Date(latestEvent.timestamp)

        anomalies.push(this.createCorrelationAnomaly(
          title,
          description,
          [], // Event-based correlation
          patterns.riskScore,
          [
            { type: 'ip', id: ip, name: ip }
          ],
          evidence,
          recommendations,
          eventTimestamp
        ))
      }
    }

    return anomalies
  }

  private analyzeIpPatterns(events: AuthEvent[]): {
    riskScore: number
    description: string
    riskFactors: string[]
    uniqueUsers: Set<string>
    uniqueHosts: Set<string>
    failedLogons: number
    successfulLogons: number
    patterns: string[]
  } {
    const uniqueUsers = new Set<string>()
    const uniqueHosts = new Set<string>()
    const patterns: string[] = []
    const riskFactors: string[] = []

    let failedLogons = 0
    let successfulLogons = 0
    let privilegeEscalations = 0
    let accountLockouts = 0
    let rapidAttempts = 0

    // Sort events by timestamp
    const sortedEvents = events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())

    events.forEach(event => {
      if (event.userName) uniqueUsers.add(event.userName)
      if (event.computerName) uniqueHosts.add(event.computerName)

      // Count different types of events
      if (event.status === 'Failed') {
        failedLogons++
      } else if (event.status === 'Success') {
        successfulLogons++
      }

      // Detect privilege escalation patterns
      if (event.eventId === '4672' || event.eventId === '4732') {
        privilegeEscalations++
      }

      // Account lockouts
      if (event.eventId === '4740') {
        accountLockouts++
      }
    })

    // Analyze time-based patterns (brute force detection)
    let lastEventTime = 0
    let rapidSequenceCount = 0

    sortedEvents.forEach(event => {
      const eventTime = new Date(event.timestamp).getTime()

      if (lastEventTime > 0) {
        const timeDiff = eventTime - lastEventTime

        // Rapid sequence (less than 1 second between attempts)
        if (timeDiff < 1000) {
          rapidSequenceCount++
        }
      }

      lastEventTime = eventTime
    })

    if (rapidSequenceCount >= 5) {
      rapidAttempts = rapidSequenceCount
      patterns.push('rapid-fire attempts')
    }

    // Calculate risk factors
    let riskScore = 0

    // Multiple users from same IP
    if (uniqueUsers.size >= this.thresholds.minUniqueUsers) {
      riskScore += 0.3
      riskFactors.push(`${uniqueUsers.size} unique users targeted`)
      patterns.push('multi-user targeting')
    }

    // Multiple hosts from same IP
    if (uniqueHosts.size >= this.thresholds.minUniqueHosts) {
      riskScore += 0.25
      riskFactors.push(`${uniqueHosts.size} unique hosts accessed`)
      patterns.push('multi-host scanning')
    }

    // High failure rate
    const failureRate = failedLogons / events.length
    if (failureRate > 0.8) {
      riskScore += 0.2
      riskFactors.push(`${Math.round(failureRate * 100)}% failure rate`)
      patterns.push('high failure rate')
    }

    // Successful logons after failures (potential brute force success)
    if (failedLogons >= 10 && successfulLogons >= 1) {
      riskScore += 0.15
      riskFactors.push('successful logons after failures')
      patterns.push('brute force success')
    }

    // Privilege escalation activity
    if (privilegeEscalations >= 2) {
      riskScore += 0.2
      riskFactors.push(`${privilegeEscalations} privilege escalations`)
      patterns.push('privilege escalation')
    }

    // Account lockout patterns
    if (accountLockouts >= 3) {
      riskScore += 0.15
      riskFactors.push(`${accountLockouts} account lockouts`)
      patterns.push('account lockout pattern')
    }

    // Time-based rapid attempts
    if (rapidAttempts >= 5) {
      riskScore += 0.1
      riskFactors.push(`${rapidAttempts} rapid attempts`)
    }

    // Create description based on patterns
    let description = ''
    if (patterns.length > 0) {
      description = `suspicious patterns: ${patterns.join(', ')}`
    } else {
      description = `${events.length} authentication events`
    }

    return {
      riskScore: Math.min(1, riskScore),
      description,
      riskFactors,
      uniqueUsers,
      uniqueHosts,
      failedLogons,
      successfulLogons,
      patterns
    }
  }
}
