import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, CertificateEvent, ADCSContext, ESCDetectionResult } from '../types'

export class ESC1Rule extends BaseRule {
  // Client authentication EKUs that make ESC1 dangerous
  private readonly clientAuthEKUs = [
    '1.3.6.1.5.5.7.3.2',  // Client Authentication
    '1.3.6.1.5.2.3.4',    // PKINIT Client Authentication
    '1.3.6.1.4.1.311.20.2.2', // Smart Card Logon
    '2.5.29.37.0'         // Any Purpose
  ]

  constructor() {
    super({
      id: 'esc1_vulnerable_template_detection',
      name: 'ESC1 - Vulnerable Certificate Template (Authentication)',
      description: 'Detects certificate requests using templates that allow enrollee-supplied SANs without manager approval',
      category: 'security',
      severity: 'critical',
      timeWindow: 60, // 1 hour for certificate request analysis
      thresholds: {
        minRequestsForPattern: 1,
        suspiciousSANCount: 3,
        privilegedUserBonus: 2,
        largeGroupBonus: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects ESC1 vulnerabilities where certificate templates allow enrollee-supplied Subject Alternative Names (SANs) without manager approval. This critical vulnerability enables low-privileged users to request certificates for privileged accounts, leading to domain-wide privilege escalation and unauthorized access.',
        detectionLogic: 'Multi-layered ESC1 detection: (1) Template configuration analysis for dangerous combinations (ENROLLEE_SUPPLIES_SUBJECT flag, no manager approval, client auth EKUs), (2) Event pattern analysis for suspicious SAN usage, (3) RAW DATABASE ANALYSIS - Direct ADCS database inspection for UPN manipulation, privileged account impersonation, and manual SAN injection patterns. Correlates Windows events with raw certificate database data for comprehensive ESC1 coverage.',
        falsePositives: 'Legitimate certificate requests from authorized users, properly configured certificate templates with appropriate approval workflows, or certificate requests that follow organizational security policies. May also trigger during legitimate certificate renewal or system administration activities.',
        mitigation: [
          'Disable ENROLLEE_SUPPLIES_SUBJECT flag on vulnerable templates',
          'Enable manager approval for certificate requests',
          'Remove client authentication EKUs from vulnerable templates',
          'Implement strict certificate template permissions',
          'Use Locksmith to identify and remediate ESC1 vulnerabilities',
          'Monitor certificate requests from non-privileged users',
          'Implement certificate request approval workflows',
          'Regular AD CS security assessments and template auditing',
          'Configure certificate template restrictions in Group Policy',
          'Enable AD CS auditing for certificate requests and issuances'
        ],
        windowsEvents: ['4886 (Certificate Services Started)', '4887 (Certificate Issued)', '4888 (Certificate Services Denied)', '53 (Certificate Request)', '54 (Certificate Issued)', '4898 (Certificate Template Security Updated)', '4899 (Certificate Template Updated)', 'RAW DATABASE: Direct ADCS database analysis for SAN manipulation detection'],
        exampleQuery: `index=windows EventCode=4887 | stats count by CertificateTemplate, SubjectAlternativeName | where SubjectAlternativeName != "" | eval is_suspicious=if(match(SubjectAlternativeName, "(?i)(admin|domain|root)"), 1, 0) | where is_suspicious=1`,
        recommendedThresholds: {
          minRequestsForPattern: 1,
          suspiciousSANCount: 3,
          privilegedUserBonus: 2,
          largeGroupBonus: 1
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
      const esc1Detection = this.detectESC1Vulnerability(templateEvents, templateName, adcsContext)

      if (esc1Detection) {
        const anomaly = this.createESC1Anomaly(esc1Detection, templateEvents, adcsContext)
        anomalies.push(anomaly)
      }
    })

    return anomalies
  }

  private isCertificateEvent(event: AuthEvent): boolean {
    // Check for ADCS-related event IDs
    const adcsEventIds = ['4886', '4887', '4888', '53', '54']
    const certificateEvent = event as CertificateEvent

    const isADCSEvent = event.eventId ? adcsEventIds.includes(event.eventId) : false
    const hasTemplate = certificateEvent.certificateTemplate !== undefined
    const isRawADCS = (certificateEvent as any).eventType === 'RawADCS'
    const hasSAN = certificateEvent.subjectAlternativeNames ? certificateEvent.subjectAlternativeNames.length > 0 : false

    return isADCSEvent || hasTemplate || isRawADCS || hasSAN
  }

  private groupByTemplate(events: CertificateEvent[]): Record<string, CertificateEvent[]> {
    const groups: Record<string, CertificateEvent[]> = {}

    events.forEach(event => {
      let templateName = event.certificateTemplate || event.rawData?.certificateTemplate || 'Unknown'

      // Handle RawADCS events
      if ((event as any).eventType === 'RawADCS') {
        templateName = event.rawData?.template || event.certificateTemplate || 'Unknown'
      }

      if (!groups[templateName]) {
        groups[templateName] = []
      }
      groups[templateName].push(event)
    })

    return groups
  }

  private detectESC1Vulnerability(
    events: CertificateEvent[],
    templateName: string,
    context: ADCSContext
  ): ESCDetectionResult | null {
    // Check for RawADCS events with direct ESC1 indicators
    const rawADCSEvents = events.filter(event => (event as any).eventType === 'RawADCS')
    if (rawADCSEvents.length > 0) {
      return this.detectESC1FromRawDatabase(rawADCSEvents, templateName, context)
    }

    // Find the template configuration
    const template = context.certificateTemplates?.find(t =>
      t.name === templateName || t.displayName === templateName
    )

    if (!template) {
      // If we don't have template info, look for patterns in the events themselves
      return this.detectESC1FromEvents(events, templateName)
    }

    // Check if template has ESC1 characteristics
    const hasEnrolleeSuppliesSubject = (template.certificateNameFlags & 1) !== 0
    const hasManagerApproval = (template.enrollmentFlags & 2) !== 0
    const hasClientAuthEKU = template.extendedKeyUsage?.some(eku =>
      this.clientAuthEKUs.includes(eku)
    )

    if (!hasEnrolleeSuppliesSubject || hasManagerApproval || !hasClientAuthEKU) {
      return null
    }

    // Calculate risk score based on template configuration
    let riskScore = 4 // Base critical risk
    let confidence = 90

    // Check if template is enabled
    if (template.enabled) {
      riskScore += 1
      confidence += 10
    } else {
      riskScore -= 2 // Disabled templates are less risky
      confidence -= 20
    }

    // Check accessibility (this would normally come from template permissions)
    // For now, we'll assume some defaults
    const accessibleByLargeGroups = this.isAccessibleByLargeGroups(template)
    if (accessibleByLargeGroups) {
      riskScore += this.thresholds.largeGroupBonus
      confidence += 15
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
      confidence += 20
    }

    // Ensure risk score doesn't exceed critical
    riskScore = Math.min(riskScore, 5)

    return {
      vulnerability: 'ESC1',
      severity: riskScore >= 4 ? 'critical' : riskScore >= 3 ? 'high' : 'medium',
      confidence: Math.min(confidence, 100),
      affectedEntities: [
        {
          type: 'certificateTemplate',
          id: template.name,
          name: template.displayName || template.name
        },
        ...events.slice(0, 5).map(event => ({
          type: 'user' as const,
          id: event.userName || 'unknown',
          name: event.userName || 'Unknown User'
        }))
      ],
      evidence: {
        templateName: template.name,
        certificateNameFlags: template.certificateNameFlags,
        enrollmentFlags: template.enrollmentFlags,
        extendedKeyUsage: template.extendedKeyUsage,
        hasEnrolleeSuppliesSubject,
        hasManagerApproval,
        hasClientAuthEKU,
        totalRequests: events.length,
        privilegedRequests: privilegedRequests.length,
        accessibleByLargeGroups,
        sampleRequests: events.slice(0, 3).map(event => ({
          userName: event.userName,
          timestamp: event.timestamp,
          subjectAlternativeNames: event.subjectAlternativeNames
        }))
      },
      remediation: [
        'Enable Manager Approval for the certificate template',
        'Remove ENROLLEE_SUPPLIES_SUBJECT flag from certificate template',
        'Restrict template permissions to specific users/groups',
        'Monitor certificate requests for suspicious SAN values',
        'Consider disabling the template if not required'
      ]
    }
  }

  private detectESC1FromEvents(events: CertificateEvent[], templateName: string): ESCDetectionResult | null {
    // Look for patterns in events that suggest ESC1 vulnerability
    const suspiciousRequests = events.filter(event => {
      // Look for requests with unusual SAN patterns
      const sans = event.subjectAlternativeNames || []
      return sans.length > this.thresholds.suspiciousSANCount ||
             sans.some(san => this.isSuspiciousSAN(san))
    })

    if (suspiciousRequests.length < this.thresholds.minRequestsForPattern) {
      return null
    }

    // Check for multiple different domains in SANs (common ESC1 attack pattern)
    const allSANs = events.flatMap(event => event.subjectAlternativeNames || [])
    const uniqueDomains = new Set(
      allSANs.map(san => this.extractDomainFromSAN(san)).filter(Boolean)
    )

    if (uniqueDomains.size > 1) {
      return {
        vulnerability: 'ESC1',
        severity: 'high',
        confidence: 75,
        affectedEntities: [
          {
            type: 'certificateTemplate',
            id: templateName,
            name: templateName
          }
        ],
        evidence: {
          templateName,
          suspiciousRequests: suspiciousRequests.length,
          uniqueDomains: Array.from(uniqueDomains),
          totalSANs: allSANs.length,
          detectionMethod: 'event_pattern_analysis'
        },
        remediation: [
          'Verify certificate template configuration',
          'Check if template allows enrollee-supplied SANs without approval',
          'Review template permissions and EKUs',
          'Monitor for additional suspicious certificate requests'
        ]
      }
    }

    return null
  }

  private detectESC1FromRawDatabase(
    events: CertificateEvent[],
    templateName: string,
    context: ADCSContext
  ): ESCDetectionResult | null {
    // Analyze raw database ESC1 indicators
    const suspiciousEvents = events.filter(event =>
      event.rawData?.isSuspicious === true ||
      (event as any).isSuspiciousUPN === true ||
      (event as any).isPrivilegedTarget === true
    )

    if (suspiciousEvents.length === 0) {
      return null
    }

    // Calculate risk score based on raw database findings
    let riskScore = 5 // High base risk for raw database ESC1 detection
    let confidence = 95 // High confidence from direct database analysis

    // Boost risk score for privileged targets
    const privilegedTargets = events.filter(event => (event as any).isPrivilegedTarget === true)
    if (privilegedTargets.length > 0) {
      riskScore = Math.min(riskScore + 2, 5)
      confidence = Math.min(confidence + 10, 100)
    }

    // Boost risk score for UPN mismatches
    const upnMismatches = events.filter(event => (event as any).isSuspiciousUPN === true)
    if (upnMismatches.length > 0) {
      riskScore = Math.min(riskScore + 1, 5)
      confidence = Math.min(confidence + 5, 100)
    }

    return {
      vulnerability: 'ESC1',
      severity: riskScore >= 4 ? 'critical' : riskScore >= 3 ? 'high' : 'medium',
      confidence: confidence,
      affectedEntities: [
        {
          type: 'certificateTemplate',
          id: templateName,
          name: templateName
        },
        ...suspiciousEvents.slice(0, 5).map(event => ({
          type: 'user' as const,
          id: (event as any).requester || event.rawData?.requester || 'unknown',
          name: (event as any).requester || event.rawData?.requester || 'Unknown User'
        }))
      ],
      evidence: {
        templateName,
        detectionMethod: 'raw_database_analysis',
        totalRawEvents: events.length,
        suspiciousEvents: suspiciousEvents.length,
        upnMismatches: upnMismatches.length,
        privilegedTargets: privilegedTargets.length,
        sampleIndicators: suspiciousEvents.slice(0, 3).map(event => ({
          requester: (event as any).requester || event.rawData?.requester,
          upn: (event as any).subjectAltName || event.rawData?.upn,
          isSuspiciousUPN: (event as any).isSuspiciousUPN,
          isPrivilegedTarget: (event as any).isPrivilegedTarget,
          context: event.rawData?.context
        }))
      },
      remediation: [
        'Immediate: Disable vulnerable certificate template',
        'Review certificate requests with manual SAN settings',
        'Audit all certificates issued with suspicious SAN values',
        'Enable manager approval for certificate requests',
        'Implement certificate request approval workflows',
        'Monitor for additional UPN manipulation attempts',
        'Review CA server security and access controls'
      ]
    }
  }

  private isSuspiciousSAN(san: string): boolean {
    // Look for suspicious patterns in SAN values
    const suspiciousPatterns = [
      /admin/i,
      /root/i,
      /domain/i,
      /enterprise/i,
      /\..*\./, // Multiple subdomains
      /[^\w.-]/ // Special characters
    ]

    return suspiciousPatterns.some(pattern => pattern.test(san))
  }

  private extractDomainFromSAN(san: string): string | null {
    // Extract domain from SAN (e.g., user@domain.com -> domain.com)
    const emailMatch = san.match(/@(.+)$/)
    if (emailMatch) return emailMatch[1]

    // Extract domain from DNS name (e.g., host.domain.com -> domain.com)
    const dnsMatch = san.match(/\.(.+\..+)$/)
    if (dnsMatch) return dnsMatch[1]

    return null
  }

  private isAccessibleByLargeGroups(template: any): boolean {
    // This would check template permissions in a real implementation
    // For now, we'll use some heuristics based on template name
    const largeGroupTemplates = [
      /user/i,
      /computer/i,
      /domain/i,
      /authenticated/i
    ]

    return largeGroupTemplates.some(pattern =>
      pattern.test(template.name) || pattern.test(template.displayName || '')
    )
  }

  private createESC1Anomaly(
    detection: ESCDetectionResult,
    events: CertificateEvent[],
    context: ADCSContext
  ): Anomaly {
    const hasRawDatabaseData = events.some(event => (event as any).eventType === 'RawADCS')

    const title = hasRawDatabaseData
      ? `🚨 CRITICAL: ESC1 Detected via Raw Database Analysis - ${detection.affectedEntities[0].name}`
      : `🚨 ESC1 Vulnerability: ${detection.affectedEntities[0].name}`

    const description = hasRawDatabaseData
      ? `RAW DATABASE ANALYSIS: Certificate template ${detection.affectedEntities[0].name} shows evidence of ESC1 exploitation. ` +
        `Direct ADCS database inspection revealed ${detection.evidence.suspiciousEvents} suspicious certificate requests ` +
        `with manual SAN manipulation, including ${detection.evidence.upnMismatches} UPN mismatches and ` +
        `${detection.evidence.privilegedTargets} privileged account targets.`
      : `Certificate template ${detection.affectedEntities[0].name} is vulnerable to ESC1 attacks. ` +
        `Allows enrollee-supplied SANs without manager approval, enabling potential privilege escalation through certificate authentication.`

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
        detectionMethod: hasRawDatabaseData ? 'raw_database_analysis' : 'certificate_template_analysis',
        evidence: detection.evidence
      },
      detection.confidence,
      {
        attackType: 'certificate_template_exploit',
        vulnerabilityType: 'ESC1',
        riskLevel: detection.severity,
        rawDatabaseAnalysis: hasRawDatabaseData
      }
    )
  }
}
