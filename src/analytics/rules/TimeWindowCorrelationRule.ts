import { CorrelationRule } from './CorrelationRule'
import { AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class TimeWindowCorrelationRule extends CorrelationRule {
  constructor() {
    super(
      'time-window-alert-correlation',
      'Time Window Alert Correlation',
      'Detects rapid sequences of alerts from the same entities within short time windows',
      'high',
      30, // 30 minute time window
      {
        minAlerts: 4,
        timeWindowMinutes: 15,
        confidenceThreshold: 0.75,
        maxTimeBetweenAlerts: 5 // minutes
      },
      {
        overview: 'Detects rapid sequences of security alerts from the same user/host combinations within short time windows, indicating potential automated attacks, malware activity, or compromised credentials. Analyzes temporal patterns to identify burst activity that may indicate coordinated security incidents.',
        detectionLogic: 'Correlates security events within configurable time windows, identifying rapid sequences of alerts from the same entities. Analyzes event clustering, temporal patterns, and frequency of security events to detect potential automated attacks, malware infections, or compromised credential usage.',
        falsePositives: 'Legitimate administrative activities performed rapidly by authorized users, automated system maintenance tasks, legitimate bulk operations, or normal business processes that involve multiple security events in sequence. May also trigger during legitimate user activities or system administration tasks.',
        mitigation: [
          'Immediately investigate the source of rapid alert sequences',
          'Check affected systems for malware or unauthorized processes',
          'Review user authentication patterns and credential usage',
          'Implement rate limiting for authentication and system access',
          'Enable enhanced monitoring for affected user accounts',
          'Conduct forensic analysis of affected systems and user activities',
          'Implement automated response for rapid alert sequences',
          'Review and optimize security monitoring thresholds',
          'Enable detailed audit logging for rapid event sequences',
          'Conduct security awareness training for rapid activity detection'
        ],
        windowsEvents: ['4624 (Account Logon Success)', '4625 (Account Logon Failure)', '4672 (Special Privileges Assigned)', '4673 (Sensitive Privilege Use)', '4720 (User Account Created)', '4722 (User Account Enabled)', '4724 (Password Reset Attempted)', '4725 (Account Disabled)', '4732 (Member Added to Local Group)', '4740 (Account Locked Out)', '4771 (Kerberos Pre-auth Failed)', '4648 (Explicit Credential Logon)', '4656 (Handle to Object Requested)'],
        exampleQuery: `index=windows | bucket span=5m _time | stats count by TargetUserName, Computer | where count > 10`,
        recommendedThresholds: {
          minAlerts: 4,
          timeWindowMinutes: 15,
          confidenceThreshold: 0.75,
          maxTimeBetweenAlerts: 5
        }
      }
    )
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Group events by user and host combinations
    const entityGroups = new Map<string, AuthEvent[]>()

    events.forEach(event => {
      if (!event.userName || !event.computerName) return

      const key = `${event.userName.toLowerCase()}@${event.computerName.toLowerCase()}`
      if (!entityGroups.has(key)) {
        entityGroups.set(key, [])
      }
      entityGroups.get(key)!.push(event)
    })

    // Analyze each entity group for time-based patterns
    for (const [entityKey, entityEvents] of Array.from(entityGroups)) {
      const [userName, computerName] = entityKey.split('@')

      if (entityEvents.length < this.thresholds.minAlerts) continue

      // Sort events by timestamp
      const sortedEvents = entityEvents.sort((a, b) =>
        new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      )

      // Find rapid sequences
      const sequences = this.findRapidSequences(sortedEvents)

      sequences.forEach(sequence => {
        if (sequence.events.length >= this.thresholds.minAlerts) {
          const riskScore = this.calculateSequenceRisk(sequence)

          if (riskScore >= this.thresholds.confidenceThreshold) {
            const title = `⚡ Rapid Alert Sequence: ${userName} on ${computerName}`
            const description = `User ${userName} on host ${computerName} triggered ${sequence.events.length} alerts in ${sequence.duration} minutes. This may indicate automated attacks, malware activity, or compromised credentials.`

            const evidence = {
              userName,
              computerName,
              sequenceLength: sequence.events.length,
              durationMinutes: sequence.duration,
              riskScore,
              eventTypes: sequence.eventTypes,
              timeSpan: `${sequence.startTime.toISOString()} to ${sequence.endTime.toISOString()}`,
              patterns: sequence.patterns
            }

            const recommendations = [
              `Investigate immediate activity for user ${userName} on ${computerName}`,
              'Check for malware or automated attack tools',
              'Review system logs for unusual processes or network connections',
              'Consider temporarily disabling the account if compromise is suspected',
              'Monitor for similar patterns across the network'
            ]

            // Use the latest event timestamp from the sequence
            const eventTimestamp = new Date(sequence.events[0].timestamp)

            anomalies.push(this.createCorrelationAnomaly(
              title,
              description,
              [], // Event-based correlation
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
      })
    }

    return anomalies
  }

  private findRapidSequences(events: AuthEvent[]): Array<{
    events: AuthEvent[]
    startTime: Date
    endTime: Date
    duration: number
    eventTypes: Set<string>
    patterns: string[]
  }> {
    const sequences: Array<{
      events: AuthEvent[]
      startTime: Date
      endTime: Date
      duration: number
      eventTypes: Set<string>
      patterns: string[]
    }> = []

    const maxTimeGap = this.thresholds.maxTimeBetweenAlerts * 60 * 1000 // Convert to milliseconds

    let currentSequence: AuthEvent[] = []
    let sequenceStartTime: Date | null = null

    for (let i = 0; i < events.length; i++) {
      const currentEvent = events[i]
      const currentTime = new Date(currentEvent.timestamp).getTime()

      if (currentSequence.length === 0) {
        // Start new sequence
        currentSequence = [currentEvent]
        sequenceStartTime = new Date(currentEvent.timestamp)
      } else {
        const lastEventTime = new Date(currentSequence[currentSequence.length - 1].timestamp).getTime()
        const timeGap = currentTime - lastEventTime

        if (timeGap <= maxTimeGap) {
          // Continue sequence
          currentSequence.push(currentEvent)
        } else {
          // End current sequence and start new one
          if (currentSequence.length >= 2) {
            sequences.push(this.createSequenceObject(currentSequence, sequenceStartTime!))
          }
          currentSequence = [currentEvent]
          sequenceStartTime = new Date(currentEvent.timestamp)
        }
      }
    }

    // Don't forget the last sequence
    if (currentSequence.length >= 2) {
      sequences.push(this.createSequenceObject(currentSequence, sequenceStartTime!))
    }

    return sequences
  }

  private createSequenceObject(events: AuthEvent[], startTime: Date): {
    events: AuthEvent[]
    startTime: Date
    endTime: Date
    duration: number
    eventTypes: Set<string>
    patterns: string[]
  } {
    const endTime = new Date(events[events.length - 1].timestamp)
    const duration = (endTime.getTime() - startTime.getTime()) / (1000 * 60) // minutes

    const eventTypes = new Set(events.map(e => e.eventId))
    const patterns: string[] = []

    // Analyze patterns in the sequence
    const failedCount = events.filter(e => e.status === 'Failed').length
    const successCount = events.filter(e => e.status === 'Success').length

    if (failedCount > successCount * 2) {
      patterns.push('high failure rate')
    }

    if (eventTypes.has('4625') && eventTypes.has('4624')) {
      patterns.push('failed then successful logon')
    }

    if (eventTypes.has('4672')) {
      patterns.push('privilege escalation')
    }

    if (events.length >= 10) {
      patterns.push('high volume')
    }

    return {
      events,
      startTime,
      endTime,
      duration,
      eventTypes,
      patterns
    }
  }

  private calculateSequenceRisk(sequence: {
    events: AuthEvent[]
    duration: number
    eventTypes: Set<string>
    patterns: string[]
  }): number {
    let riskScore = 0

    // Base score from sequence length
    riskScore += Math.min(0.3, sequence.events.length * 0.05)

    // Short duration increases risk
    if (sequence.duration <= 5) {
      riskScore += 0.2
    } else if (sequence.duration <= 10) {
      riskScore += 0.1
    }

    // Risk patterns
    sequence.patterns.forEach(pattern => {
      switch (pattern) {
        case 'high failure rate':
          riskScore += 0.15
          break
        case 'failed then successful logon':
          riskScore += 0.2
          break
        case 'privilege escalation':
          riskScore += 0.25
          break
        case 'high volume':
          riskScore += 0.1
          break
      }
    })

    // Multiple event types increase risk (diversity of suspicious activity)
    if (sequence.eventTypes.size >= 3) {
      riskScore += 0.1
    }

    return Math.min(1, riskScore)
  }
}
