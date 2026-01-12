import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, CertificateEvent, ADCSContext, ESCDetectionResult } from '../types'

export class ESC3Rule extends BaseRule {
  // Enrollment Agent EKU
  private readonly enrollmentAgentEKU = '1.3.6.1.4.1.311.20.2.1'

  // Client authentication EKUs that make ESC3 dangerous when combined with enrollment agents
  private readonly clientAuthEKUs = [
    '1.3.6.1.5.5.7.3.2',  // Client Authentication
    '1.3.6.1.5.2.3.4',    // PKINIT Client Authentication
    '1.3.6.1.4.1.311.20.2.2', // Smart Card Logon
    '2.5.29.37.0'         // Any Purpose
  ]

  constructor() {
    super({
      id: 'esc3_enrollment_agent_detection',
      name: 'ESC3 - Vulnerable Enrollment Agent Templates',
      description: 'Detects certificate requests using enrollment agent templates that can be abused for privilege escalation',
      category: 'security',
      severity: 'critical',
      timeWindow: 60, // 1 hour for certificate request analysis
      thresholds: {
        minRequestsForPattern: 1,
        condition2Bonus: 2, // Higher risk for Condition 2
        privilegedAgentBonus: 1,
        multipleTargetsBonus: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects ESC3 vulnerabilities in enrollment agent certificate templates that can be abused for privilege escalation. Enrollment agents allow users to request certificates on behalf of others, but misconfigurations can enable attackers to obtain certificates for privileged accounts without proper authorization.',
        detectionLogic: 'Analyzes two ESC3 conditions: (1) Enrollment agent certificates issued without manager approval or authorized signature, (2) Certificate templates allowing enrollment agents to request client authentication certificates without approval. Monitors certificate requests and issuances to identify exploitation attempts.',
        falsePositives: 'Legitimate enrollment agent usage by authorized personnel, properly configured certificate templates with appropriate approval workflows, or certificate requests that follow organizational security policies. May also trigger during legitimate certificate renewal or system administration activities.',
        mitigation: [
          'Enable manager approval for enrollment agent certificate requests',
          'Configure authorized signature requirements for enrollment agents',
          'Restrict enrollment agent template permissions to authorized users',
          'Disable client authentication EKUs on enrollment agent-accessible templates',
          'Implement strict enrollment agent certificate lifecycle management',
          'Use Locksmith to identify and remediate ESC3 vulnerabilities',
          'Monitor enrollment agent certificate usage and requests',
          'Implement certificate request approval workflows',
          'Regular AD CS security assessments and template auditing',
          'Configure enrollment agent restrictions in Group Policy'
        ],
        windowsEvents: ['4886 (Certificate Services Started)', '4887 (Certificate Issued)', '4888 (Certificate Services Backup Started)', '53 (Certificate Request)', '54 (Certificate Issued)', '4898 (Certificate Template Loaded)', '4899 (Certificate Template Updated)', '4648 (Explicit Credential Logon)', '4672 (Admin Logon)'],
        exampleQuery: `index=windows EventCode=4887 | stats count by CertificateTemplate, ExtendedKeyUsage | where ExtendedKeyUsage="*1.3.6.1.4.1.311.20.2.1*"`,
        recommendedThresholds: {
          minRequestsForPattern: 1,
          condition2Bonus: 2,
          privilegedAgentBonus: 1,
          multipleTargetsBonus: 1
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    const adcsContext = context as ADCSContext

    // Filter certificate-related events
    const certificateEvents = events.filter(event =>
      this.isCertificateEvent(event)
    ) as CertificateEvent[]

    if (certificateEvents.length === 0) return anomalies

    // Check for ESC3 Condition 1: Enrollment Agent certificates issued without approval
    const esc3Condition1Anomalies = this.detectESC3Condition1(certificateEvents, adcsContext)
    anomalies.push(...esc3Condition1Anomalies)

    // Check for ESC3 Condition 2: Templates allowing enrollment agents to enroll for client auth
    const esc3Condition2Anomalies = this.detectESC3Condition2(certificateEvents, adcsContext)
    anomalies.push(...esc3Condition2Anomalies)

    return anomalies
  }

  private isCertificateEvent(event: AuthEvent): boolean {
    // Check for ADCS-related event IDs
    const adcsEventIds = ['4886', '4887', '4888', '53', '54']
    return adcsEventIds.includes(event.eventId) ||
           (event as CertificateEvent).certificateTemplate !== undefined
  }

  private detectESC3Condition1(
    events: CertificateEvent[],
    context: ADCSContext
  ): Anomaly[] {
    const anomalies: Anomaly[] = []

    // Look for enrollment agent certificates issued
    const enrollmentAgentCertificates = events.filter(event =>
      event.extendedKeyUsage?.includes(this.enrollmentAgentEKU) &&
      event.status === 'Success'
    )

    if (enrollmentAgentCertificates.length === 0) return anomalies

    // Group by template
    const templateGroups = this.groupByTemplate(enrollmentAgentCertificates)

    Object.entries(templateGroups).forEach(([templateName, templateEvents]) => {
      // Check if template allows issuance without manager approval
      const template = context.certificateTemplates?.find(t =>
        t.name === templateName || t.displayName === templateName
      )

      const hasManagerApproval = template ? (template.enrollmentFlags & 2) !== 0 : false
      const hasRASignature = template ? (template.enrollmentFlags & 1) !== 0 : false

      // ESC3 Condition 1: No manager approval AND no authorized signature required
      if (!hasManagerApproval && !hasRASignature) {
        let riskScore = 3 // Base high risk
        let confidence = 80

        // Check if enrollment agent certificates were issued to privileged users
        const privilegedAgents = templateEvents.filter(event => {
          const userProfile = context.userProfiles?.find(u =>
            u.userName === event.userName && u.domain === event.domainName
          )
          return userProfile?.privileged
        })

        if (privilegedAgents.length > 0) {
          riskScore += this.thresholds.privilegedAgentBonus
          confidence += 15
        }

        // Check if agents have been used to request other certificates
        const agentUsage = this.detectAgentUsage(templateEvents, events)
        if (agentUsage.hasBeenUsed) {
          riskScore += 1
          confidence += 10
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'ESC3',
          severity: riskScore >= 4 ? 'critical' : 'high',
          confidence: Math.min(confidence, 100),
          affectedEntities: [
            {
              type: 'certificateTemplate',
              id: templateName,
              name: templateName
            },
            ...templateEvents.slice(0, 3).map(event => ({
              type: 'user' as const,
              id: event.userName || 'unknown',
              name: event.userName || 'Unknown User'
            }))
          ],
          evidence: {
            templateName,
            condition: 'ESC3-Condition1',
            enrollmentAgentCertificates: templateEvents.length,
            privilegedAgents: privilegedAgents.length,
            hasManagerApproval,
            hasRASignature,
            agentUsage: agentUsage,
            sampleCertificates: templateEvents.slice(0, 3).map(event => ({
              userName: event.userName,
              requestId: event.requestId,
              timestamp: event.timestamp
            }))
          },
          remediation: [
            'Enable Manager Approval for enrollment agent template',
            'Require authorized signature for enrollment agent certificates',
            'Restrict enrollment agent template to specific privileged users',
            'Monitor usage of issued enrollment agent certificates',
            'Consider implementing enrollment agent restrictions'
          ]
        }

        const anomaly = this.createESC3Anomaly(detection, templateEvents, context)
        anomalies.push(anomaly)
      }
    })

    return anomalies
  }

  private detectESC3Condition2(
    events: CertificateEvent[],
    context: ADCSContext
  ): Anomaly[] {
    const anomalies: Anomaly[] = []

    // Look for client authentication certificates that could be requested via enrollment agent
    const clientAuthCertificates = events.filter(event =>
      event.extendedKeyUsage?.some(eku => this.clientAuthEKUs.includes(eku)) &&
      event.status === 'Success'
    )

    if (clientAuthCertificates.length === 0) return anomalies

    // Group by template
    const templateGroups = this.groupByTemplate(clientAuthCertificates)

    Object.entries(templateGroups).forEach(([templateName, templateEvents]) => {
      const template = context.certificateTemplates?.find(t =>
        t.name === templateName || t.displayName === templateName
      )

      if (!template) return

      // Check if template allows enrollment via enrollment agent
      const hasManagerApproval = (template.enrollmentFlags & 2) !== 0
      const hasEnrollmentAgentRestriction = template.applicationPolicies?.includes(this.enrollmentAgentEKU)

      // ESC3 Condition 2: Client auth template allows enrollment agents AND no manager approval
      if (hasEnrollmentAgentRestriction && !hasManagerApproval) {
        let riskScore = 4 // Base critical risk (ESC3 Condition 2 is very dangerous)
        let confidence = 85

        // Higher risk for ESC3 Condition 2
        riskScore += this.thresholds.condition2Bonus

        // Check if certificates were issued to multiple different users (indicating agent usage)
        const uniqueUsers = new Set(templateEvents.map(e => e.userName).filter(Boolean))
        if (uniqueUsers.size > 1) {
          riskScore += this.thresholds.multipleTargetsBonus
          confidence += 15
        }

        // Check for suspicious certificate usage patterns
        const suspiciousUsage = this.detectSuspiciousUsage(templateEvents)
        if (suspiciousUsage.hasSuspiciousPatterns) {
          riskScore += 1
          confidence += 10
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'ESC3',
          severity: 'critical',
          confidence: Math.min(confidence, 100),
          affectedEntities: [
            {
              type: 'certificateTemplate',
              id: templateName,
              name: template.displayName || templateName
            },
            ...Array.from(uniqueUsers).slice(0, 3).map(user => ({
              type: 'user' as const,
              id: user as string,
              name: user as string
            }))
          ],
          evidence: {
            templateName,
            condition: 'ESC3-Condition2',
            clientAuthCertificates: templateEvents.length,
            uniqueUsers: uniqueUsers.size,
            hasManagerApproval,
            hasEnrollmentAgentRestriction,
            applicationPolicies: template.applicationPolicies,
            suspiciousUsage: suspiciousUsage,
            sampleCertificates: templateEvents.slice(0, 3).map(event => ({
              userName: event.userName,
              subjectName: event.subjectName,
              requestId: event.requestId,
              timestamp: event.timestamp
            }))
          },
          remediation: [
            'Enable Manager Approval for the client authentication template',
            'Remove enrollment agent restrictions from client auth templates',
            'Restrict template permissions to prevent unauthorized enrollment agent usage',
            'Implement certificate request validation',
            'Monitor for suspicious certificate authentication patterns'
          ]
        }

        const anomaly = this.createESC3Anomaly(detection, templateEvents, context)
        anomalies.push(anomaly)
      }
    })

    return anomalies
  }

  private groupByTemplate(events: CertificateEvent[]): Record<string, CertificateEvent[]> {
    const groups: Record<string, CertificateEvent[]> = {}

    events.forEach(event => {
      const templateName = event.certificateTemplate || event.rawData?.certificateTemplate || 'Unknown'
      if (!groups[templateName]) {
        groups[templateName] = []
      }
      groups[templateName].push(event)
    })

    return groups
  }

  private detectAgentUsage(agentCertificates: CertificateEvent[], allEvents: CertificateEvent[]): {
    hasBeenUsed: boolean
    usageCount: number
    targetUsers: string[]
  } {
    // Look for certificates requested by these enrollment agents
    const agentUsers = new Set(agentCertificates.map(c => c.userName).filter(Boolean))
    const agentRequestedCertificates = allEvents.filter(event =>
      event.userName && agentUsers.has(event.userName) &&
      !event.extendedKeyUsage?.includes(this.enrollmentAgentEKU) // Not enrollment agent certs themselves
    )

    return {
      hasBeenUsed: agentRequestedCertificates.length > 0,
      usageCount: agentRequestedCertificates.length,
      targetUsers: Array.from(new Set(agentRequestedCertificates.map(c => c.userName).filter(Boolean))) as string[]
    }
  }

  private detectSuspiciousUsage(events: CertificateEvent[]): {
    hasSuspiciousPatterns: boolean
    patterns: string[]
  } {
    const patterns: string[] = []

    // Check for rapid certificate requests (potential automation)
    const timestamps = events.map(e => new Date(e.timestamp).getTime()).sort()
    let rapidRequests = 0

    for (let i = 1; i < timestamps.length; i++) {
      if (timestamps[i] - timestamps[i-1] < 60000) { // Less than 1 minute apart
        rapidRequests++
      }
    }

    if (rapidRequests > 2) {
      patterns.push('rapid_certificate_requests')
    }

    // Check for unusual subject names
    const unusualSubjects = events.filter(event => {
      const subject = event.subjectName || ''
      return subject.includes('admin') || subject.includes('root') ||
             subject.includes('system') || subject.includes('svc')
    })

    if (unusualSubjects.length > 0) {
      patterns.push('suspicious_subject_names')
    }

    return {
      hasSuspiciousPatterns: patterns.length > 0,
      patterns
    }
  }

  private createESC3Anomaly(
    detection: ESCDetectionResult,
    events: CertificateEvent[],
    context: ADCSContext
  ): Anomaly {
    const condition = detection.evidence.condition
    const title = `🚨 ESC3 Vulnerability (${condition}): ${detection.affectedEntities[0].name}`
    const description = `Certificate template ${detection.affectedEntities[0].name} is vulnerable to ESC3 ${condition} attacks. ` +
      `Enrollment agent certificates can be abused for privilege escalation by requesting certificates on behalf of other users.`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: detection.vulnerability,
        condition: detection.evidence.condition,
        severity: detection.severity,
        confidence: detection.confidence,
        templateName: detection.affectedEntities[0].name,
        totalRequests: events.length,
        timeWindow: this.timeWindow,
        detectionMethod: 'enrollment_agent_analysis',
        evidence: detection.evidence
      },
      detection.confidence,
      {
        attackType: 'enrollment_agent_exploit',
        vulnerabilityType: 'ESC3',
        riskLevel: detection.severity
      }
    )
  }
}
