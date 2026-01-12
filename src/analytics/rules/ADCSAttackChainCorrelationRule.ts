import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, ESCDetectionResult } from '../types'
import { ADCSEventIds } from '../types'

export class ADCSAttackChainCorrelationRule extends BaseRule {
  constructor() {
    super({
      id: 'adcs_attack_chain_correlation',
      name: 'AD CS Attack Chain Correlation',
      description: 'Detects multi-stage AD CS attack chains and suspicious event sequences',
      category: 'security',
      severity: 'critical',
      timeWindow: 120, // 2 hours for attack chain analysis
      thresholds: {
        minEventsInChain: 3,
        maxTimeWindowMinutes: 60,
        suspiciousSequenceBonus: 2,
        toolToCertCorrelationBonus: 3,
        templateToIssuanceBonus: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects sophisticated multi-stage Active Directory Certificate Services (AD CS) attack chains and suspicious event sequences. AD CS has become a primary attack vector for advanced persistent threats, enabling attackers to obtain legitimate certificates for privilege escalation and persistence.',
        detectionLogic: 'Correlates AD CS events across time windows to identify attack patterns such as certificate template exploitation, enrollment agent abuse, CA compromise sequences, and certificate-based lateral movement. Analyzes event sequences, tool usage patterns, and certificate lifecycle correlations to detect complex attack chains.',
        falsePositives: 'Legitimate certificate management operations, automated certificate renewals, system administration tasks, and approved certificate requests. May also trigger during legitimate PKI maintenance or certificate lifecycle management activities.',
        mitigation: [
          'Implement certificate template hardening using Locksmith recommendations',
          'Disable vulnerable certificate templates (ESC1-ESC16)',
          'Configure restricted enrollment agent permissions',
          'Enable AD CS auditing and monitoring',
          'Implement certificate request approval workflows',
          'Use certificate-based authentication with strong binding',
          'Monitor for suspicious certificate requests and issuances',
          'Regular AD CS security assessments with Locksmith',
          'Implement certificate revocation monitoring',
          'Use conditional access policies for certificate-based authentication'
        ],
        windowsEvents: ['4886 (Certificate Services Started)', '4887 (Certificate Services Stopped)', '4888 (Certificate Services Backup Started)', '4889 (Certificate Services Restore Started)', '4890 (Certificate Services Backup Completed)', '4891 (Certificate Services Restore Completed)', '4898 (Certificate Template Loaded)', '4899 (Certificate Template Updated)', '53 (Certificate Request)', '54 (Certificate Issued)'],
        exampleQuery: `index=windows EventCode=4887 OR EventCode=54 | transaction TargetUserName maxspan=1h | where eventcount > 3`,
        recommendedThresholds: {
          minEventsInChain: 3,
          maxTimeWindowMinutes: 60,
          suspiciousSequenceBonus: 2,
          toolToCertCorrelationBonus: 3,
          templateToIssuanceBonus: 1
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Analyze attack chains
    const attackChains = this.detectAttackChains(events)
    attackChains.forEach(chain => {
      const anomaly = this.createAttackChainAnomaly(chain, context)
      anomalies.push(anomaly)
    })

    // Analyze suspicious sequences
    const suspiciousSequences = this.detectSuspiciousSequences(events)
    suspiciousSequences.forEach(sequence => {
      const anomaly = this.createSequenceAnomaly(sequence, context)
      anomalies.push(anomaly)
    })

    // Analyze tool-to-certificate correlations
    const toolCertCorrelations = this.detectToolCertificateCorrelations(events)
    toolCertCorrelations.forEach(correlation => {
      const anomaly = this.createToolCertAnomaly(correlation, context)
      anomalies.push(anomaly)
    })

    return anomalies
  }

  private detectAttackChains(events: AuthEvent[]): AttackChain[] {
    const attackChains: AttackChain[] = []

    // Look for multi-stage attack patterns
    const adcsEvents = events.filter(event =>
      event.eventId === ADCSEventIds.CERTIFICATE_REQUEST_RECEIVED ||
      event.eventId === ADCSEventIds.CERTIFICATE_ISSUED ||
      event.eventId === ADCSEventIds.CERTIFICATE_TEMPLATE_PERMISSIONS_CHANGED ||
      event.eventId === ADCSEventIds.CERTIFICATE_TEMPLATE_UPDATED ||
      event.eventId === ADCSEventIds.CA_BACKUP_STARTED ||
      event.eventId === ADCSEventIds.CA_BACKUP_COMPLETED ||
      event.eventId === ADCSEventIds.CERTIFICATE_EXPORT ||
      event.eventId === ADCSEventIds.POWERSHELL_SCRIPT_BLOCK ||
      event.eventId === ADCSEventIds.PROCESS_CREATION
    )

    // Group events by user within time window
    const userEventMap = new Map<string, AuthEvent[]>()

    adcsEvents.forEach(event => {
      const userKey = event.userName || event.rawData?.userName || 'unknown'
      if (!userEventMap.has(userKey)) {
        userEventMap.set(userKey, [])
      }
      userEventMap.get(userKey)!.push(event)
    })

    // Analyze each user's activity for attack chains
    for (const [userName, userEvents] of Array.from(userEventMap.entries())) {
      if (userEvents.length >= this.thresholds.minEventsInChain) {
        const sortedEvents = userEvents.sort((a, b) =>
          new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
        )

        const userChains = this.identifyAttackChains(sortedEvents, userName)
        userChains.forEach(chain => {
          if (chain.events.length >= this.thresholds.minEventsInChain) {
            attackChains.push(chain)
          }
        })
      }
    }

    return attackChains
  }

  private identifyAttackChains(events: AuthEvent[], userName: string): AttackChain[] {
    const chains: AttackChain[] = []
    let currentChain: AttackChain | null = null

    for (let i = 0; i < events.length; i++) {
      const event = events[i]
      const eventTime = new Date(event.timestamp).getTime()

      // Check if this event belongs to current chain or starts a new one
      if (currentChain) {
        const chainStartTime = new Date(currentChain.events[0].timestamp).getTime()
        const timeDiff = eventTime - chainStartTime

        if (timeDiff <= this.thresholds.maxTimeWindowMinutes * 60 * 1000) {
          // Add to current chain
          currentChain.events.push(event)
          currentChain.patterns = this.updateChainPatterns(currentChain.patterns, event)
          currentChain.confidence = this.calculateChainConfidence(currentChain)
        } else {
          // Chain too long, start new one
          if (currentChain.events.length >= this.thresholds.minEventsInChain) {
            chains.push(currentChain)
          }
          currentChain = this.createNewChain(event, userName)
        }
      } else {
        // Start new chain
        currentChain = this.createNewChain(event, userName)
      }
    }

    // Add final chain if it meets minimum requirements
    if (currentChain && currentChain.events.length >= this.thresholds.minEventsInChain) {
      chains.push(currentChain)
    }

    return chains
  }

  private createNewChain(event: AuthEvent, userName: string): AttackChain {
    return {
      id: `chain_${userName}_${Date.now()}`,
      userName,
      events: [event],
      patterns: this.identifyEventPatterns([event]),
      confidence: 50,
      riskLevel: 'medium',
      startTime: event.timestamp.toISOString(),
      endTime: event.timestamp.toISOString()
    }
  }

  private updateChainPatterns(existingPatterns: string[], newEvent: AuthEvent): string[] {
    const patterns = [...existingPatterns]
    const eventId = newEvent.eventId

    // Template modification patterns
    if (eventId === ADCSEventIds.CERTIFICATE_TEMPLATE_PERMISSIONS_CHANGED ||
        eventId === ADCSEventIds.CERTIFICATE_TEMPLATE_UPDATED) {
      if (!patterns.includes('template_modification')) {
        patterns.push('template_modification')
      }
    }

    // Certificate request/issuance patterns
    if (eventId === ADCSEventIds.CERTIFICATE_REQUEST_RECEIVED ||
        eventId === ADCSEventIds.CERTIFICATE_ISSUED) {
      if (!patterns.includes('certificate_operations')) {
        patterns.push('certificate_operations')
      }
    }

    // Tool usage patterns
    if (eventId === ADCSEventIds.PROCESS_CREATION) {
      if (!patterns.includes('tool_usage')) {
        patterns.push('tool_usage')
      }
    }

    // Export patterns
    if (eventId === ADCSEventIds.CERTIFICATE_EXPORT) {
      if (!patterns.includes('certificate_export')) {
        patterns.push('certificate_export')
      }
    }

    // Backup patterns
    if (eventId === ADCSEventIds.CA_BACKUP_STARTED ||
        eventId === ADCSEventIds.CA_BACKUP_COMPLETED) {
      if (!patterns.includes('ca_backup')) {
        patterns.push('ca_backup')
      }
    }

    return patterns
  }

  private identifyEventPatterns(events: AuthEvent[]): string[] {
    const patterns: string[] = []

    events.forEach(event => {
      const eventId = event.eventId

      if (eventId === ADCSEventIds.CERTIFICATE_TEMPLATE_PERMISSIONS_CHANGED ||
          eventId === ADCSEventIds.CERTIFICATE_TEMPLATE_UPDATED) {
        patterns.push('template_modification')
      }

      if (eventId === ADCSEventIds.CERTIFICATE_REQUEST_RECEIVED ||
          eventId === ADCSEventIds.CERTIFICATE_ISSUED) {
        patterns.push('certificate_operations')
      }

      if (eventId === ADCSEventIds.PROCESS_CREATION) {
        patterns.push('tool_usage')
      }

      if (eventId === ADCSEventIds.CERTIFICATE_EXPORT) {
        patterns.push('certificate_export')
      }

      if (eventId === ADCSEventIds.CA_BACKUP_STARTED ||
          eventId === ADCSEventIds.CA_BACKUP_COMPLETED) {
        patterns.push('ca_backup')
      }
    })

    return Array.from(new Set(patterns)) // Remove duplicates
  }

  private calculateChainConfidence(chain: AttackChain): number {
    let confidence = 50

    // Base confidence on number of events
    confidence += Math.min(chain.events.length * 10, 30)

    // Bonus for suspicious patterns
    if (chain.patterns.includes('template_modification') &&
        chain.patterns.includes('certificate_operations')) {
      confidence += this.thresholds.suspiciousSequenceBonus
    }

    if (chain.patterns.includes('tool_usage') &&
        chain.patterns.includes('certificate_operations')) {
      confidence += this.thresholds.toolToCertCorrelationBonus
    }

    if (chain.patterns.includes('template_modification') &&
        chain.patterns.includes('certificate_export')) {
      confidence += this.thresholds.templateToIssuanceBonus
    }

    return Math.min(confidence, 100)
  }

  private detectSuspiciousSequences(events: AuthEvent[]): SuspiciousSequence[] {
    const sequences: SuspiciousSequence[] = []

    // Pattern 1: Template modification followed by certificate request/issuance
    const templateModSeq = this.findSequencePattern(events, [
      ADCSEventIds.CERTIFICATE_TEMPLATE_PERMISSIONS_CHANGED,
      ADCSEventIds.CERTIFICATE_TEMPLATE_UPDATED
    ], [
      ADCSEventIds.CERTIFICATE_REQUEST_RECEIVED,
      ADCSEventIds.CERTIFICATE_ISSUED
    ])

    if (templateModSeq) {
      sequences.push({
        type: 'template_mod_to_cert_ops',
        description: 'Template modification followed by certificate operations',
        events: templateModSeq.events,
        confidence: 85,
        riskLevel: 'high'
      })
    }

    // Pattern 2: Tool usage followed by certificate operations
    const toolToCertSeq = this.findSequencePattern(events, [
      ADCSEventIds.PROCESS_CREATION
    ], [
      ADCSEventIds.CERTIFICATE_REQUEST_RECEIVED,
      ADCSEventIds.CERTIFICATE_ISSUED,
      ADCSEventIds.CERTIFICATE_EXPORT
    ])

    if (toolToCertSeq) {
      sequences.push({
        type: 'tool_to_cert_ops',
        description: 'Certificate tool usage followed by certificate operations',
        events: toolToCertSeq.events,
        confidence: 90,
        riskLevel: 'critical'
      })
    }

    // Pattern 3: Multiple template modifications
    const multiTemplateSeq = this.findMultiEventPattern(events, [
      ADCSEventIds.CERTIFICATE_TEMPLATE_PERMISSIONS_CHANGED,
      ADCSEventIds.CERTIFICATE_TEMPLATE_UPDATED
    ], 3)

    if (multiTemplateSeq) {
      sequences.push({
        type: 'multiple_template_mods',
        description: 'Multiple template modifications in sequence',
        events: multiTemplateSeq.events,
        confidence: 75,
        riskLevel: 'medium'
      })
    }

    return sequences
  }

  private findSequencePattern(events: AuthEvent[], firstEventTypes: string[], secondEventTypes: string[]): SequencePattern | null {
    for (let i = 0; i < events.length - 1; i++) {
      const firstEvent = events[i]
      if (!firstEventTypes.includes(firstEvent.eventId)) continue

      for (let j = i + 1; j < events.length; j++) {
        const secondEvent = events[j]
        if (!secondEventTypes.includes(secondEvent.eventId)) continue

        const timeDiff = new Date(secondEvent.timestamp).getTime() - new Date(firstEvent.timestamp).getTime()
        if (timeDiff <= this.thresholds.maxTimeWindowMinutes * 60 * 1000) {
          return {
            events: [firstEvent, secondEvent],
            timeSpan: timeDiff
          }
        }
      }
    }
    return null
  }

  private findMultiEventPattern(events: AuthEvent[], eventTypes: string[], minCount: number): SequencePattern | null {
    const matchingEvents = events.filter(event => eventTypes.includes(event.eventId))

    if (matchingEvents.length >= minCount) {
      const sortedEvents = matchingEvents.sort((a, b) =>
        new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      )

      const timeSpan = new Date(sortedEvents[sortedEvents.length - 1].timestamp).getTime() -
                      new Date(sortedEvents[0].timestamp).getTime()

      if (timeSpan <= this.thresholds.maxTimeWindowMinutes * 60 * 1000) {
        return {
          events: sortedEvents,
          timeSpan
        }
      }
    }

    return null
  }

  private detectToolCertificateCorrelations(events: AuthEvent[]): ToolCertCorrelation[] {
    const correlations: ToolCertCorrelation[] = []

    const toolEvents = events.filter(event =>
      event.eventId === ADCSEventIds.PROCESS_CREATION &&
      this.isCertificateTool(event)
    )

    const certEvents = events.filter(event =>
      event.eventId === ADCSEventIds.CERTIFICATE_REQUEST_RECEIVED ||
      event.eventId === ADCSEventIds.CERTIFICATE_ISSUED ||
      event.eventId === ADCSEventIds.CERTIFICATE_EXPORT
    )

    toolEvents.forEach(toolEvent => {
      const toolTime = new Date(toolEvent.timestamp).getTime()
      const toolUser = toolEvent.userName || toolEvent.rawData?.userName

      const correlatedCerts = certEvents.filter(certEvent => {
        const certTime = new Date(certEvent.timestamp).getTime()
        const certUser = certEvent.userName || certEvent.rawData?.userName

        const timeDiff = Math.abs(certTime - toolTime)
        return certUser === toolUser &&
               timeDiff <= this.thresholds.maxTimeWindowMinutes * 60 * 1000
      })

      if (correlatedCerts.length > 0) {
        correlations.push({
          toolEvent,
          certificateEvents: correlatedCerts,
          timeSpan: Math.max(...correlatedCerts.map(e =>
            Math.abs(new Date(e.timestamp).getTime() - toolTime)
          )),
          userName: toolUser || 'unknown'
        })
      }
    })

    return correlations
  }

  private isCertificateTool(event: AuthEvent): boolean {
    const processName = event.rawData?.processName || ''
    return processName.toLowerCase().includes('certipy') ||
           processName.toLowerCase().includes('mimikatz') ||
           processName.toLowerCase().includes('certify') ||
           processName.toLowerCase().includes('certutil')
  }

  private createAttackChainAnomaly(chain: AttackChain, context: AnalyticsContext): Anomaly {
    const title = `🔗 AD CS Attack Chain: ${chain.userName}`
    const description = `Multi-stage AD CS attack chain detected for user ${chain.userName}. ` +
      `Chain contains ${chain.events.length} events with patterns: ${chain.patterns.join(', ')}`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: 'AD CS Attack Chain' as any,
        severity: this.getSeverityFromRiskLevel(chain.riskLevel),
        confidence: chain.confidence,
        affectedEntity: chain.userName,
        timeWindow: this.timeWindow,
        detectionMethod: 'adcs_attack_chain_correlation',
        evidence: {
          chainId: chain.id,
          eventCount: chain.events.length,
          patterns: chain.patterns,
          timeSpan: `${new Date(chain.startTime).toISOString()} to ${new Date(chain.endTime).toISOString()}`,
          events: chain.events.map(event => ({
            timestamp: event.timestamp,
            eventId: event.eventId,
            description: this.getEventDescription(event.eventId)
          }))
        }
      },
      chain.confidence,
      {
        attackType: 'adcs_attack_chain',
        vulnerabilityType: 'AD CS Attack Chain',
        riskLevel: chain.riskLevel
      }
    )
  }

  private createSequenceAnomaly(sequence: SuspiciousSequence, context: AnalyticsContext): Anomaly {
    const title = `⚠️ Suspicious AD CS Sequence: ${sequence.type}`
    const description = sequence.description

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: 'AD CS Suspicious Sequence' as any,
        severity: this.getSeverityFromRiskLevel(sequence.riskLevel),
        confidence: sequence.confidence,
        affectedEntity: sequence.events[0]?.userName || 'unknown',
        timeWindow: this.timeWindow,
        detectionMethod: 'adcs_sequence_detection',
        evidence: {
          sequenceType: sequence.type,
          eventCount: sequence.events.length,
          events: sequence.events.map(event => ({
            timestamp: event.timestamp,
            eventId: event.eventId,
            description: this.getEventDescription(event.eventId)
          }))
        }
      },
      sequence.confidence,
      {
        attackType: 'adcs_suspicious_sequence',
        vulnerabilityType: 'AD CS Suspicious Sequence',
        riskLevel: sequence.riskLevel
      }
    )
  }

  private createToolCertAnomaly(correlation: ToolCertCorrelation, context: AnalyticsContext): Anomaly {
    const title = `🛠️ Tool-Certificate Correlation: ${correlation.userName}`
    const description = `Certificate tool usage correlated with certificate operations for user ${correlation.userName}`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: 'Tool-Certificate Correlation' as any,
        severity: 'critical',
        confidence: 95,
        affectedEntity: correlation.userName,
        timeWindow: this.timeWindow,
        detectionMethod: 'tool_certificate_correlation',
        evidence: {
          toolEvent: {
            timestamp: correlation.toolEvent.timestamp,
            tool: correlation.toolEvent.rawData?.processName,
            commandLine: correlation.toolEvent.rawData?.commandLine
          },
          certificateEvents: correlation.certificateEvents.map(event => ({
            timestamp: event.timestamp,
            eventId: event.eventId,
            description: this.getEventDescription(event.eventId)
          })),
          timeSpanMinutes: Math.round(correlation.timeSpan / (1000 * 60))
        }
      },
      95,
      {
        attackType: 'tool_certificate_correlation',
        vulnerabilityType: 'Tool-Certificate Correlation',
        riskLevel: 'critical'
      }
    )
  }

  private getEventDescription(eventId: string): string {
    const descriptions: { [key: string]: string } = {
      [ADCSEventIds.CERTIFICATE_REQUEST_RECEIVED]: 'Certificate request received',
      [ADCSEventIds.CERTIFICATE_ISSUED]: 'Certificate issued',
      [ADCSEventIds.CERTIFICATE_TEMPLATE_PERMISSIONS_CHANGED]: 'Template permissions changed',
      [ADCSEventIds.CERTIFICATE_TEMPLATE_UPDATED]: 'Template updated',
      [ADCSEventIds.CA_BACKUP_STARTED]: 'CA backup started',
      [ADCSEventIds.CA_BACKUP_COMPLETED]: 'CA backup completed',
      [ADCSEventIds.CERTIFICATE_EXPORT]: 'Certificate exported',
      [ADCSEventIds.POWERSHELL_SCRIPT_BLOCK]: 'PowerShell script executed',
      [ADCSEventIds.PROCESS_CREATION]: 'Process created'
    }
    return descriptions[eventId] || `Event ${eventId}`
  }

  private getSeverityFromRiskLevel(riskLevel: string): 'low' | 'medium' | 'high' | 'critical' {
    switch (riskLevel) {
      case 'critical': return 'critical'
      case 'high': return 'high'
      case 'medium': return 'medium'
      default: return 'low'
    }
  }
}

// Type definitions
interface AttackChain {
  id: string
  userName: string
  events: AuthEvent[]
  patterns: string[]
  confidence: number
  riskLevel: string
  startTime: string
  endTime: string
}

interface SuspiciousSequence {
  type: string
  description: string
  events: AuthEvent[]
  confidence: number
  riskLevel: string
}

interface SequencePattern {
  events: AuthEvent[]
  timeSpan: number
}

interface ToolCertCorrelation {
  toolEvent: AuthEvent
  certificateEvents: AuthEvent[]
  timeSpan: number
  userName: string
}
