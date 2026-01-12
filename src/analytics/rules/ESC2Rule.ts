import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, CertificateEvent, ADCSContext, ESCDetectionResult } from '../types'

export class ESC2Rule extends BaseRule {
  // EKUs that make templates vulnerable to ESC2
  private readonly vulnerableEKUs = [
    '2.5.29.37.0'  // Any Purpose EKU
  ]

  // EKUs that indicate SubCA capabilities
  private readonly subcaEKUs = [
    '1.3.6.1.5.5.7.3.9',  // OCSP Signing
    '1.3.6.1.5.5.7.3.28', // Time Stamping
    '1.3.6.1.4.1.311.10.3.4', // Encrypting File System
    '1.3.6.1.4.1.311.10.3.4.1' // File Recovery
  ]

  constructor() {
    super({
      id: 'esc2_subca_template_detection',
      name: 'ESC2 - Vulnerable SubCA/Any Purpose Templates',
      description: 'Detects certificate requests using templates with Any Purpose EKU or missing EKUs that can create SubCA certificates',
      category: 'security',
      severity: 'critical',
      timeWindow: 60, // 1 hour for certificate request analysis
      thresholds: {
        minRequestsForPattern: 1,
        subcaCapabilityBonus: 2,
        noEKUBonus: 1,
        privilegedUserBonus: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects ESC2 vulnerabilities where certificate templates have "Any Purpose" Extended Key Usage (EKU) or missing EKUs, allowing attackers to create subordinate Certificate Authorities (SubCAs). This critical vulnerability enables complete compromise of the AD CS infrastructure and domain-wide privilege escalation.',
        detectionLogic: 'Analyzes certificate template configurations for dangerous EKU combinations: (1) "Any Purpose" (2.5.29.37.0) EKU present, (2) No specific EKU restrictions, (3) SubCA-capable EKUs (OCSP Signing, Time Stamping, etc.). Monitors certificate requests using vulnerable templates to identify potential SubCA creation attempts.',
        falsePositives: 'Legitimate certificate templates with appropriate EKU restrictions, properly configured certificate issuance policies, or certificate requests that follow organizational security policies. May also trigger during legitimate SubCA deployment or certificate lifecycle management activities.',
        mitigation: [
          'Remove "Any Purpose" EKU from vulnerable certificate templates',
          'Configure specific EKU restrictions on certificate templates',
          'Disable SubCA-capable EKUs on user-accessible templates',
          'Implement strict certificate template permissions and access controls',
          'Use Locksmith to identify and remediate ESC2 vulnerabilities',
          'Enable manager approval for SubCA-capable certificate requests',
          'Monitor certificate requests with SubCA EKUs',
          'Regular AD CS template security assessments and auditing',
          'Configure certificate template restrictions in Group Policy',
          'Implement certificate request approval workflows for high-risk templates'
        ],
        windowsEvents: ['4886 (Certificate Services Started)', '4887 (Certificate Issued)', '4888 (Certificate Services Backup Started)', '53 (Certificate Request)', '54 (Certificate Issued)', '4898 (Certificate Template Loaded)', '4899 (Certificate Template Updated)', '4876 (Certificate Services Backup Started)', '4877 (Certificate Services Backup Completed)'],
        exampleQuery: `index=windows EventCode=4887 | stats count by CertificateTemplate, ExtendedKeyUsage | where ExtendedKeyUsage="*2.5.29.37.0*"`,
        recommendedThresholds: {
          minRequestsForPattern: 1,
          subcaCapabilityBonus: 2,
          noEKUBonus: 1,
          privilegedUserBonus: 1
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

    // Group by certificate template
    const templateGroups = this.groupByTemplate(certificateEvents)

    Object.entries(templateGroups).forEach(([templateName, templateEvents]) => {
      const esc2Detection = this.detectESC2Vulnerability(templateEvents, templateName, adcsContext)

      if (esc2Detection) {
        const anomaly = this.createESC2Anomaly(esc2Detection, templateEvents, adcsContext)
        anomalies.push(anomaly)
      }
    })

    return anomalies
  }

  private isCertificateEvent(event: AuthEvent): boolean {
    // Check for ADCS-related event IDs
    const adcsEventIds = ['4886', '4887', '4888', '53', '54']
    return adcsEventIds.includes(event.eventId) ||
           (event as CertificateEvent).certificateTemplate !== undefined
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

  private detectESC2Vulnerability(
    events: CertificateEvent[],
    templateName: string,
    context: ADCSContext
  ): ESCDetectionResult | null {
    // Find the template configuration
    const template = context.certificateTemplates?.find(t =>
      t.name === templateName || t.displayName === templateName
    )

    if (!template) {
      // If we don't have template info, look for patterns in the events themselves
      return this.detectESC2FromEvents(events, templateName)
    }

    // Check if template has ESC2 characteristics
    const hasAnyPurposeEKU = template.extendedKeyUsage?.some(eku =>
      this.vulnerableEKUs.includes(eku)
    )
    const hasNoEKU = !template.extendedKeyUsage || template.extendedKeyUsage.length === 0
    const hasManagerApproval = (template.enrollmentFlags & 2) !== 0
    const hasSubCACapability = template.extendedKeyUsage?.some(eku =>
      this.subcaEKUs.includes(eku)
    )

    // ESC2 is triggered if:
    // 1. Template has Any Purpose EKU OR no EKU specified
    // 2. No manager approval required
    // 3. Template is enabled
    const isVulnerable = (hasAnyPurposeEKU || hasNoEKU) &&
                        !hasManagerApproval &&
                        template.enabled

    if (!isVulnerable) {
      return null
    }

    // Calculate risk score based on template configuration
    let riskScore = 3 // Base high risk
    let confidence = 85

    // Increase risk if template has SubCA capabilities
    if (hasSubCACapability) {
      riskScore += this.thresholds.subcaCapabilityBonus
      confidence += 15
    }

    // Increase risk if no EKU is specified (more dangerous)
    if (hasNoEKU) {
      riskScore += this.thresholds.noEKUBonus
      confidence += 10
    }

    // Check if any privileged users requested certificates with this template
    const privilegedRequests = events.filter(event => {
      const userProfile = context.userProfiles?.find(u =>
        u.userName === event.userName && u.domain === event.domainName
      )
      return userProfile?.privileged
    })

    if (privilegedRequests.length > 0) {
      riskScore += this.thresholds.privilegedUserBonus
      confidence += 10
    }

    // Check if template is accessible by large groups
    const accessibleByLargeGroups = this.isAccessibleByLargeGroups(template)
    if (accessibleByLargeGroups) {
      riskScore += 1
      confidence += 10
    }

    // ESC2 can lead to SubCA creation, which is very dangerous
    if (riskScore >= 5) {
      riskScore = 5 // Cap at critical
    }

    return {
      vulnerability: 'ESC2',
      severity: riskScore >= 4 ? 'critical' : riskScore >= 3 ? 'high' : 'medium',
      confidence: Math.min(confidence, 100),
      affectedEntities: [
        {
          type: 'certificateTemplate',
          id: template.name,
          name: template.displayName || template.name
        },
        ...events.slice(0, 3).map(event => ({
          type: 'user' as const,
          id: event.userName || 'unknown',
          name: event.userName || 'Unknown User'
        }))
      ],
      evidence: {
        templateName: template.name,
        extendedKeyUsage: template.extendedKeyUsage,
        enrollmentFlags: template.enrollmentFlags,
        hasAnyPurposeEKU,
        hasNoEKU,
        hasSubCACapability,
        hasManagerApproval,
        totalRequests: events.length,
        privilegedRequests: privilegedRequests.length,
        accessibleByLargeGroups,
        subcaCapabilities: template.extendedKeyUsage?.filter(eku => this.subcaEKUs.includes(eku)),
        sampleRequests: events.slice(0, 3).map(event => ({
          userName: event.userName,
          timestamp: event.timestamp,
          requestId: event.requestId
        }))
      },
      remediation: [
        'Enable Manager Approval for the certificate template',
        'Remove Any Purpose EKU from the template',
        'Specify explicit EKUs instead of Any Purpose',
        'Restrict template permissions to specific users/groups',
        'Monitor for SubCA certificate requests',
        'Consider disabling the template if SubCA capability is not required'
      ]
    }
  }

  private detectESC2FromEvents(events: CertificateEvent[], templateName: string): ESCDetectionResult | null {
    // Look for patterns in events that suggest ESC2 vulnerability

    // Check for certificates with Any Purpose EKU issued
    const anyPurposeCertificates = events.filter(event =>
      event.extendedKeyUsage?.includes('2.5.29.37.0') ||
      (!event.extendedKeyUsage || event.extendedKeyUsage.length === 0)
    )

    if (anyPurposeCertificates.length < this.thresholds.minRequestsForPattern) {
      return null
    }

    // Look for SubCA-like certificate usage patterns
    const subcaIndicators = events.filter(event => {
      const ekus = event.extendedKeyUsage || []
      return ekus.some(eku => this.subcaEKUs.includes(eku)) ||
             event.subjectName?.toLowerCase().includes('ca') ||
             event.subjectName?.toLowerCase().includes('sub')
    })

    const hasSubCAIndicators = subcaIndicators.length > 0

    return {
      vulnerability: 'ESC2',
      severity: hasSubCAIndicators ? 'critical' : 'high',
      confidence: 70,
      affectedEntities: [
        {
          type: 'certificateTemplate',
          id: templateName,
          name: templateName
        }
      ],
      evidence: {
        templateName,
        anyPurposeCertificates: anyPurposeCertificates.length,
        subcaIndicators: subcaIndicators.length,
        totalRequests: events.length,
        detectionMethod: 'event_pattern_analysis',
        hasSubCAIndicators
      },
      remediation: [
        'Verify certificate template configuration for Any Purpose EKU',
        'Check if template allows SubCA certificate creation',
        'Enable Manager Approval if not already enabled',
        'Remove Any Purpose EKU and specify explicit EKUs',
        'Monitor for unauthorized SubCA certificate creation'
      ]
    }
  }

  private isAccessibleByLargeGroups(template: any): boolean {
    // This would check template permissions in a real implementation
    // For now, we'll use some heuristics based on template name and common patterns
    const largeGroupTemplates = [
      /subca/i,
      /ca/i,
      /computer/i,
      /domain/i,
      /authenticated/i,
      /any/i
    ]

    return largeGroupTemplates.some(pattern =>
      pattern.test(template.name) || pattern.test(template.displayName || '')
    )
  }

  private createESC2Anomaly(
    detection: ESCDetectionResult,
    events: CertificateEvent[],
    context: ADCSContext
  ): Anomaly {
    const title = `🚨 ESC2 Vulnerability: ${detection.affectedEntities[0].name}`
    const description = `Certificate template ${detection.affectedEntities[0].name} is vulnerable to ESC2 attacks. ` +
      `Contains Any Purpose EKU or missing EKUs without manager approval, allowing creation of SubCA certificates for privilege escalation.`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: detection.vulnerability,
        severity: detection.severity,
        confidence: detection.confidence,
        templateName: detection.affectedEntities[0].name,
        totalRequests: events.length,
        timeWindow: this.timeWindow,
        detectionMethod: 'certificate_template_analysis',
        evidence: detection.evidence
      },
      detection.confidence,
      {
        attackType: 'subca_certificate_exploit',
        vulnerabilityType: 'ESC2',
        riskLevel: detection.severity
      }
    )
  }
}
