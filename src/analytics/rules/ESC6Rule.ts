import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, CertificateEvent, ADCSContext, ESCDetectionResult } from '../types'

export class ESC6Rule extends BaseRule {
  // EDITF_ATTRIBUTESUBJECTALTNAME2 flag value
  private readonly EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000

  constructor() {
    super({
      id: 'esc6_editf_flag_detection',
      name: 'ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag Detection',
      description: 'Detects certificate requests that exploit CA EDITF_ATTRIBUTESUBJECTALTNAME2 flag allowing arbitrary SANs',
      category: 'security',
      severity: 'high',
      timeWindow: 60, // 1 hour for CA configuration analysis
      thresholds: {
        suspiciousSANCount: 5,
        esc1TemplateBonus: 2,
        esc9TemplateBonus: 1,
        arbitrarySANBonus: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects ESC6 vulnerabilities where Certificate Authority (CA) configurations have the EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled, allowing arbitrary Subject Alternative Names (SANs) in certificates. This critical vulnerability enables attackers to request certificates for privileged accounts without proper authorization, leading to domain-wide privilege escalation.',
        detectionLogic: 'Analyzes CA registry configurations for the EDITF_ATTRIBUTESUBJECTALTNAME2 (0x00040000) flag and monitors certificate requests for suspicious SAN patterns. Detects two ESC6 scenarios: (A) with Kerberos authentication and (B) with Schannel authentication. Correlates with ESC1 and ESC9 vulnerable templates for enhanced risk assessment.',
        falsePositives: 'Legitimate certificate requests with proper SAN values, authorized certificate issuance for legitimate purposes, or certificate requests that follow organizational security policies. May also trigger during legitimate certificate renewal or system administration activities.',
        mitigation: [
          'Disable EDITF_ATTRIBUTESUBJECTALTNAME2 flag on vulnerable CAs',
          'Configure strict SAN validation and approval workflows',
          'Monitor certificate requests with suspicious SAN patterns',
          'Implement certificate request approval for privileged account SANs',
          'Use Locksmith to identify and remediate ESC6 vulnerabilities',
          'Configure CA registry settings to restrict arbitrary SANs',
          'Enable CA auditing for certificate requests and issuances',
          'Regular AD CS security assessments and template auditing',
          'Implement certificate SAN pattern validation',
          'Configure certificate request restrictions in Group Policy'
        ],
        windowsEvents: ['4886 (Certificate Services Started)', '4887 (Certificate Issued)', '4888 (Certificate Services Backup Started)', '53 (Certificate Request)', '54 (Certificate Issued)', '4898 (Certificate Template Permissions Changed)', '4899 (Certificate Template Updated)', '4909 (Certificate Services Template Settings Changed)', '4910 (Certificate Services Template Updated)'],
        exampleQuery: `index=windows EventCode=4887 | stats count by CertificateTemplate, SubjectAlternativeName | where count > 5`,
        recommendedThresholds: {
          suspiciousSANCount: 5,
          esc1TemplateBonus: 2,
          esc9TemplateBonus: 1,
          arbitrarySANBonus: 1
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    const adcsContext = context as ADCSContext

    // Check CA configuration for EDITF_ATTRIBUTESUBJECTALTNAME2 flag
    const caConfigurationAnomalies = this.analyzeCAConfiguration(adcsContext)
    anomalies.push(...caConfigurationAnomalies)

    // Analyze certificate requests for suspicious SAN patterns
    const certificateEvents = events.filter(event =>
      this.isCertificateEvent(event)
    ) as CertificateEvent[]

    if (certificateEvents.length > 0) {
      const sanAnomalies = this.analyzeSuspiciousSANs(certificateEvents, adcsContext)
      anomalies.push(...sanAnomalies)
    }

    return anomalies
  }

  private isCertificateEvent(event: AuthEvent): boolean {
    const adcsEventIds = ['4886', '4887', '4888', '53', '54']
    return adcsEventIds.includes(event.eventId) ||
           (event as CertificateEvent).certificateTemplate !== undefined
  }

  private analyzeCAConfiguration(context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    if (!context.certificateAuthorities) return anomalies

    context.certificateAuthorities.forEach(ca => {
      // Check if EDITF_ATTRIBUTESUBJECTALTNAME2 flag is enabled
      const hasDangerousFlag = (ca.editFlags & this.EDITF_ATTRIBUTESUBJECTALTNAME2) !== 0

      if (hasDangerousFlag) {
        let riskScore = 3 // Base medium risk
        let confidence = 90
        const riskFactors: string[] = []

        // Check for ESC1 vulnerable templates in this CA
        const esc1Templates = this.findESC1Templates(context)
        if (esc1Templates.length > 0) {
          riskScore += this.thresholds.esc1TemplateBonus
          confidence += 15
          riskFactors.push(`${esc1Templates.length} ESC1 vulnerable templates available`)
        }

        // Check for ESC9 vulnerable templates
        const esc9Templates = this.findESC9Templates(context)
        if (esc9Templates.length > 0) {
          riskScore += this.thresholds.esc9TemplateBonus
          confidence += 10
          riskFactors.push(`${esc9Templates.length} ESC9 vulnerable templates available`)
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'ESC6',
          severity: riskScore >= 5 ? 'critical' : riskScore >= 4 ? 'high' : 'medium',
          confidence: Math.min(confidence, 100),
          affectedEntities: [
            {
              type: 'certificateAuthority',
              id: ca.name,
              name: ca.displayName || ca.name
            }
          ],
          evidence: {
            caName: ca.name,
            dnsName: ca.dnsName,
            editFlags: ca.editFlags,
            hasEDITF_ATTRIBUTESUBJECTALTNAME2: hasDangerousFlag,
            esc1Templates: esc1Templates.map(t => t.name),
            esc9Templates: esc9Templates.map(t => t.name),
            riskFactors,
            caConfiguration: {
              auditFilter: ca.auditFilter,
              interfaceFlags: ca.interfaceFlags,
              securityFlags: ca.securityFlags
            }
          },
          remediation: [
            `Disable EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA: ${ca.name}`,
            'Run: certutil -config "CAHostName\\CAName" -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2',
            'Restart Certificate Services after flag removal',
            'Review and secure ESC1/ESC9 vulnerable templates',
            'Enable Manager Approval on vulnerable templates',
            'Implement certificate request validation'
          ]
        }

        const anomaly = this.createESC6Anomaly(detection, context)
        anomalies.push(anomaly)
      }
    })

    return anomalies
  }

  private analyzeSuspiciousSANs(events: CertificateEvent[], context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    // Look for certificates with suspicious SAN patterns that might exploit EDITF flag
    const suspiciousCertRequests = events.filter(event => {
      const sans = event.subjectAlternativeNames || []
      return this.hasSuspiciousSANs(sans) && event.status === 'Success'
    })

    if (suspiciousCertRequests.length >= this.thresholds.suspiciousSANCount) {
      // Group by certificate authority
      const caGroups = this.groupByCA(suspiciousCertRequests)

      Object.entries(caGroups).forEach(([caName, caEvents]) => {
        const uniqueDomains = new Set<string>()
        const allSANs: string[] = []

        caEvents.forEach(event => {
          const sans = event.subjectAlternativeNames || []
          sans.forEach(san => {
            allSANs.push(san)
            const domain = this.extractDomainFromSAN(san)
            if (domain) uniqueDomains.add(domain)
          })
        })

        // Check if this CA has the dangerous flag
        const ca = context.certificateAuthorities?.find(c =>
          c.name === caName || c.dnsName === caName
        )
        const hasDangerousFlag = ca ? (ca.editFlags & this.EDITF_ATTRIBUTESUBJECTALTNAME2) !== 0 : false

        let riskScore = 2 // Base low risk for suspicious SANs
        let confidence = 70

        if (hasDangerousFlag) {
          riskScore += 2 // Significant increase if flag is enabled
          confidence += 20
        }

        if (uniqueDomains.size > 3) {
          riskScore += 1
          confidence += 10
        }

        if (caEvents.length > 10) {
          riskScore += 1
          confidence += 15
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'ESC6',
          severity: riskScore >= 4 ? 'high' : riskScore >= 3 ? 'medium' : 'low',
          confidence: Math.min(confidence, 100),
          affectedEntities: [
            {
              type: 'certificateAuthority',
              id: caName,
              name: caName
            }
          ],
          evidence: {
            caName,
            suspiciousRequests: caEvents.length,
            uniqueDomains: Array.from(uniqueDomains),
            totalSANs: allSANs.length,
            hasEDITF_ATTRIBUTESUBJECTALTNAME2: hasDangerousFlag,
            suspiciousSANs: allSANs.slice(0, 10),
            sampleRequests: caEvents.slice(0, 5).map(event => ({
              userName: event.userName,
              template: event.certificateTemplate,
              subjectName: event.subjectName,
              subjectAlternativeNames: event.subjectAlternativeNames
            }))
          },
          remediation: [
            'Verify CA configuration for EDITF_ATTRIBUTESUBJECTALTNAME2 flag',
            'Disable the flag if enabled',
            'Review certificate requests for suspicious SAN values',
            'Implement SAN validation policies',
            'Monitor certificate issuance patterns'
          ]
        }

        const anomaly = this.createESC6Anomaly(detection, context)
        anomalies.push(anomaly)
      })
    }

    return anomalies
  }

  private findESC1Templates(context: ADCSContext): any[] {
    if (!context.certificateTemplates) return []

    return context.certificateTemplates.filter(template => {
      // ESC1: ENROLLEE_SUPPLIES_SUBJECT + no manager approval + client auth EKU
      const hasEnrolleeSuppliesSubject = (template.certificateNameFlags & 1) !== 0
      const hasManagerApproval = (template.enrollmentFlags & 2) !== 0
      const hasClientAuthEKU = template.extendedKeyUsage?.some(eku =>
        ['1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2', '2.5.29.37.0'].includes(eku)
      )

      return hasEnrolleeSuppliesSubject && !hasManagerApproval && hasClientAuthEKU && template.enabled
    })
  }

  private findESC9Templates(context: ADCSContext): any[] {
    if (!context.certificateTemplates) return []

    return context.certificateTemplates.filter(template => {
      // ESC9: Weak certificate binding (szOID_NTDS_CA_SECURITY_EXT disabled)
      const enrollmentFlags = template.enrollmentFlags || 0
      const hasWeakBinding = (enrollmentFlags & 0x80000) !== 0

      return hasWeakBinding && template.enabled
    })
  }

  private hasSuspiciousSANs(sans: string[]): boolean {
    if (sans.length === 0) return false

    const suspiciousPatterns = [
      /\badmin\b/i,
      /\broot\b/i,
      /\bsystem\b/i,
      /\bdc\b/i,
      /\bsrv\b/i,
      /[^\w.-]/, // Special characters
      /\..*\./,  // Multiple subdomains
      /\b(local|localhost)\b/i
    ]

    return sans.some(san =>
      suspiciousPatterns.some(pattern => pattern.test(san))
    )
  }

  private extractDomainFromSAN(san: string): string | null {
    // Extract domain from various SAN formats
    const emailMatch = san.match(/@(.+)$/)
    if (emailMatch) return emailMatch[1]

    const dnsMatch = san.match(/\.(.+\..+)$/)
    if (dnsMatch) return dnsMatch[1]

    return null
  }

  private groupByCA(events: CertificateEvent[]): Record<string, CertificateEvent[]> {
    const groups: Record<string, CertificateEvent[]> = {}

    events.forEach(event => {
      const caName = event.certificateAuthority ||
                    event.rawData?.certificateAuthority ||
                    event.computerName ||
                    'Unknown'
      if (!groups[caName]) {
        groups[caName] = []
      }
      groups[caName].push(event)
    })

    return groups
  }

  private createESC6Anomaly(
    detection: ESCDetectionResult,
    context: ADCSContext
  ): Anomaly {
    const title = `🚨 ESC6 Vulnerability: ${detection.affectedEntities[0].name}`
    const description = `Certificate Authority ${detection.affectedEntities[0].name} has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled, ` +
      `allowing arbitrary Subject Alternative Names in certificate requests. This can be exploited for privilege escalation.`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: detection.vulnerability,
        severity: detection.severity,
        confidence: detection.confidence,
        caName: detection.affectedEntities[0].name,
        timeWindow: this.timeWindow,
        detectionMethod: 'ca_configuration_analysis',
        evidence: detection.evidence
      },
      detection.confidence,
      {
        attackType: 'arbitrary_san_exploit',
        vulnerabilityType: 'ESC6',
        riskLevel: detection.severity
      }
    )
  }
}
