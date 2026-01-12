import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, CertificateEvent, ADCSContext, ESCDetectionResult } from '../types'

export class ESC9Rule extends BaseRule {
  // szOID_NTDS_CA_SECURITY_EXT OID
  private readonly NTDS_CA_SECURITY_EXT_OID = '1.3.6.1.4.1.311.25.2'

  // Enrollment flag that controls strong certificate binding
  private readonly DISABLE_NTDS_CA_SECURITY_EXT_FLAG = 0x80000

  constructor() {
    super({
      id: 'esc9_weak_certificate_binding',
      name: 'ESC9 - Weak Certificate Binding Detection',
      description: 'Detects certificates issued without strong certificate binding (szOID_NTDS_CA_SECURITY_EXT disabled)',
      category: 'security',
      severity: 'high',
      timeWindow: 60, // 1 hour for certificate binding analysis
      thresholds: {
        weakBindingBonus: 2,
        privilegedUserBonus: 1,
        multipleCertificatesBonus: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects ESC9 vulnerabilities where certificate templates have the DISABLE_NTDS_CA_SECURITY_EXT flag enabled, causing certificates to be issued without the szOID_NTDS_CA_SECURITY_EXT extension. This extension provides strong binding between certificates and Active Directory objects, preventing impersonation attacks.',
        detectionLogic: 'Analyzes certificate template configurations for the DISABLE_NTDS_CA_SECURITY_EXT (0x80000) flag and examines issued certificates for the presence of szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2). Monitors certificate issuance from templates with weak binding that can be used for client authentication.',
        falsePositives: 'Legitimate certificates issued from properly configured templates with strong binding enabled, certificates that follow organizational security policies, or certificate requests that include appropriate security extensions. May also trigger during legitimate certificate renewal or system administration activities.',
        mitigation: [
          'Enable szOID_NTDS_CA_SECURITY_EXT on vulnerable certificate templates',
          'Remove DISABLE_NTDS_CA_SECURITY_EXT flag from template configurations',
          'Configure certificate templates to require strong certificate binding',
          'Restrict client authentication templates to require security extensions',
          'Use Locksmith to identify and remediate ESC9 vulnerabilities',
          'Monitor certificates issued without security extensions',
          'Implement certificate validation and binding verification',
          'Regular AD CS template security assessments and auditing',
          'Configure certificate template restrictions in Group Policy',
          'Enable certificate binding validation in authentication processes'
        ],
        windowsEvents: ['4887 (Certificate Issued)', '54 (Certificate Issued)', '4898 (Certificate Template Permissions Changed)', '4899 (Certificate Template Updated)', '4900 (Certificate Services Template Loaded)', '4886 (Certificate Services Started)', '4888 (Certificate Services Backup Started)', '4909 (Certificate Services Template Settings Changed)', '4910 (Certificate Services Template Updated)'],
        exampleQuery: `index=windows EventCode=4887 | stats count by CertificateTemplate, HasSecurityExtension | where HasSecurityExtension="false"`,
        recommendedThresholds: {
          weakBindingBonus: 2,
          privilegedUserBonus: 1,
          multipleCertificatesBonus: 1
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    const adcsContext = context as ADCSContext

    // Analyze certificate template configuration
    const templateAnomalies = this.analyzeCertificateTemplates(adcsContext)
    anomalies.push(...templateAnomalies)

    // Analyze issued certificates for weak binding
    const certificateEvents = events.filter(event =>
      this.isCertificateEvent(event)
    ) as CertificateEvent[]

    if (certificateEvents.length > 0) {
      const certificateAnomalies = this.analyzeIssuedCertificates(certificateEvents, adcsContext)
      anomalies.push(...certificateAnomalies)
    }

    return anomalies
  }

  private isCertificateEvent(event: AuthEvent): boolean {
    const certEventIds = ['4887', '54'] // Certificate issued events
    return certEventIds.includes(event.eventId) ||
           (event as CertificateEvent).certificateTemplate !== undefined
  }

  private analyzeCertificateTemplates(context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    if (!context.certificateTemplates) return anomalies

    const vulnerableTemplates = context.certificateTemplates.filter(template => {
      // Check if template has weak certificate binding
      const enrollmentFlags = template.enrollmentFlags || 0
      const hasWeakBinding = (enrollmentFlags & this.DISABLE_NTDS_CA_SECURITY_EXT_FLAG) !== 0

      // Check if template can be used for authentication
      const hasClientAuthEKU = template.extendedKeyUsage?.some(eku =>
        ['1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2'].includes(eku)
      )

      return template.enabled && hasWeakBinding && hasClientAuthEKU
    })

    vulnerableTemplates.forEach(template => {
      let riskScore = 3 // Base high risk for weak certificate binding
      let confidence = 85

      // Check if template requires manager approval
      const hasManagerApproval = (template.enrollmentFlags & 2) !== 0
      if (!hasManagerApproval) {
        riskScore += 1
        confidence += 10
      }

      // Check if template is accessible by large groups
      const accessibleByLargeGroups = this.isAccessibleByLargeGroups(template)
      if (accessibleByLargeGroups) {
        riskScore += 1
        confidence += 5
      }

      // Check if template has Any Purpose EKU (increases risk)
      const hasAnyPurposeEKU = template.extendedKeyUsage?.includes('2.5.29.37.0')
      if (hasAnyPurposeEKU) {
        riskScore += 1
        confidence += 10
      }

      const detection: ESCDetectionResult = {
        vulnerability: 'ESC9',
        severity: riskScore >= 5 ? 'critical' : riskScore >= 4 ? 'high' : 'medium',
        confidence: Math.min(confidence, 100),
        affectedEntities: [
          {
            type: 'certificateTemplate',
            id: template.name,
            name: template.displayName || template.name
          }
        ],
        evidence: {
          templateName: template.name,
          displayName: template.displayName,
          enrollmentFlags: template.enrollmentFlags,
          certificateNameFlags: template.certificateNameFlags,
          extendedKeyUsage: template.extendedKeyUsage,
          hasWeakBinding: true,
          hasManagerApproval,
          hasClientAuthEKU: true,
          hasAnyPurposeEKU,
          accessibleByLargeGroups,
          missingSecurityExtension: this.NTDS_CA_SECURITY_EXT_OID,
          permissions: template.permissions
        },
        remediation: [
          `Enable strong certificate binding for template: ${template.name}`,
          'Remove DISABLE_NTDS_CA_SECURITY_EXT flag (0x80000) from enrollment flags',
          'Enable Manager Approval for the template',
          'Restrict template permissions to specific users/groups',
          'Monitor for certificates issued without strong binding',
          'Consider disabling the template until properly configured'
        ]
      }

      const anomaly = this.createESC9Anomaly(detection, context)
      anomalies.push(anomaly)
    })

    return anomalies
  }

  private analyzeIssuedCertificates(events: CertificateEvent[], context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    // Look for certificates issued without the security extension
    const weakBindingCertificates = events.filter(event => {
      // Check if certificate was issued successfully
      if (event.status !== 'Success') return false

      // Check if certificate lacks the security extension
      const extensions = event.rawData?.extensions || []
      const hasSecurityExt = extensions.some((ext: any) =>
        ext.oid === this.NTDS_CA_SECURITY_EXT_OID
      )

      // Also check EKU to see if this could be used for authentication
      const hasClientAuthEKU = event.extendedKeyUsage?.some(eku =>
        ['1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2'].includes(eku)
      )

      return !hasSecurityExt && hasClientAuthEKU
    })

    if (weakBindingCertificates.length > 0) {
      // Group by certificate template
      const templateGroups = this.groupByTemplate(weakBindingCertificates)

      Object.entries(templateGroups).forEach(([templateName, templateEvents]) => {
        let riskScore = 3 // Base high risk
        let confidence = 80

        // Check if users receiving these certificates are privileged
        const privilegedUsers = templateEvents.filter(event => {
          const userProfile = context.userProfiles?.find(u =>
            u.userName === event.userName && u.domain === event.domainName
          )
          return userProfile?.privileged
        })

        if (privilegedUsers.length > 0) {
          riskScore += this.thresholds.privilegedUserBonus
          confidence += 15
        }

        // Check for multiple certificates issued
        if (templateEvents.length > 3) {
          riskScore += this.thresholds.multipleCertificatesBonus
          confidence += 10
        }

        // Check if template configuration indicates weak binding
        const template = context.certificateTemplates?.find(t =>
          t.name === templateName || t.displayName === templateName
        )

        if (template) {
          const enrollmentFlags = template.enrollmentFlags || 0
          const hasWeakBindingFlag = (enrollmentFlags & this.DISABLE_NTDS_CA_SECURITY_EXT_FLAG) !== 0
          if (hasWeakBindingFlag) {
            riskScore += this.thresholds.weakBindingBonus
            confidence += 20
          }
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'ESC9',
          severity: riskScore >= 5 ? 'critical' : riskScore >= 4 ? 'high' : 'medium',
          confidence: Math.min(confidence, 100),
          affectedEntities: [
            {
              type: 'certificateTemplate',
              id: templateName,
              name: templateName
            },
            ...Array.from(new Set(templateEvents.map(e => e.userName).filter(Boolean))).slice(0, 3).map(user => ({
              type: 'user' as const,
              id: user as string,
              name: user as string
            }))
          ],
          evidence: {
            templateName,
            weakBindingCertificates: templateEvents.length,
            privilegedUsers: privilegedUsers.length,
            totalAffectedUsers: new Set(templateEvents.map(e => e.userName).filter(Boolean)).size,
            certificates: templateEvents.map(event => ({
              requestId: event.requestId,
              userName: event.userName,
              serialNumber: event.serialNumber,
              thumbprint: event.thumbprint,
              timestamp: event.timestamp,
              hasSecurityExtension: false
            })),
            missingExtension: this.NTDS_CA_SECURITY_EXT_OID,
            templateHasWeakBinding: template ?
              ((template.enrollmentFlags || 0) & this.DISABLE_NTDS_CA_SECURITY_EXT_FLAG) !== 0 : false
          },
          remediation: [
            'Immediately revoke certificates issued without strong binding',
            'Fix certificate template configuration to enable szOID_NTDS_CA_SECURITY_EXT',
            'Remove DISABLE_NTDS_CA_SECURITY_EXT flag from template',
            'Re-issue certificates with proper security extensions',
            'Monitor authentication attempts using weak certificates',
            'Implement certificate validation policies'
          ]
        }

        const anomaly = this.createESC9Anomaly(detection, context)
        anomalies.push(anomaly)
      })
    }

    return anomalies
  }

  private isAccessibleByLargeGroups(template: any): boolean {
    if (!template.permissions) return false

    const largeGroups = [
      'Domain Users',
      'Authenticated Users',
      'Everyone',
      'Users'
    ]

    return template.permissions.some((perm: any) =>
      largeGroups.some(group => perm.identity.includes(group))
    )
  }

  private groupByTemplate(events: CertificateEvent[]): Record<string, CertificateEvent[]> {
    const groups: Record<string, CertificateEvent[]> = {}

    events.forEach(event => {
      const templateName = event.certificateTemplate || 'Unknown'
      if (!groups[templateName]) {
        groups[templateName] = []
      }
      groups[templateName].push(event)
    })

    return groups
  }

  private createESC9Anomaly(
    detection: ESCDetectionResult,
    context: ADCSContext
  ): Anomaly {
    const title = `🚨 ESC9 Vulnerability: Weak Certificate Binding`
    const description = `Certificate template ${detection.affectedEntities[0].name} is configured without strong certificate binding. ` +
      `Certificates issued from this template lack the szOID_NTDS_CA_SECURITY_EXT extension, making them vulnerable to privilege escalation attacks.`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: detection.vulnerability,
        severity: detection.severity,
        confidence: detection.confidence,
        templateName: detection.affectedEntities[0].name,
        timeWindow: this.timeWindow,
        detectionMethod: 'certificate_binding_analysis',
        evidence: detection.evidence
      },
      detection.confidence,
      {
        attackType: 'weak_certificate_binding',
        vulnerabilityType: 'ESC9',
        riskLevel: detection.severity
      }
    )
  }
}
