import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, CertificateEvent, ADCSContext, ESCDetectionResult } from '../types'

export class ESC15Rule extends BaseRule {
  constructor() {
    super({
      id: 'esc15_schema_v1_detection',
      name: 'ESC15/EKUwu - Schema V1 Template Detection',
      description: 'Detects Schema Version 1 certificate templates vulnerable to CVE-2024-49019 (EKUwu)',
      category: 'security',
      severity: 'critical',
      timeWindow: 120, // 2 hours for template analysis
      thresholds: {
        schemaV1Bonus: 3,
        arbitraryEKUBonus: 2,
        clientAuthEKUBonus: 1,
        minVulnerableTemplates: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects ESC15 vulnerabilities in Schema Version 1 certificate templates that are vulnerable to CVE-2024-49019 (EKUwu). Schema V1 templates allow attackers to request certificates with arbitrary Extended Key Usage (EKU) values, enabling privilege escalation through authentication bypasses and unauthorized access to critical systems.',
        detectionLogic: 'Analyzes certificate template configurations for schemaVersion=1 and monitors certificate requests using vulnerable templates. Detects templates that allow arbitrary EKU specification without proper restrictions, particularly those with client authentication capabilities that can be exploited for privilege escalation.',
        falsePositives: 'Schema Version 2 certificate templates that are not vulnerable, certificate requests that follow organizational security policies, or legitimate certificate issuance processes. May also trigger during legitimate certificate renewal or system administration activities.',
        mitigation: [
          'Upgrade vulnerable certificate templates to Schema Version 2',
          'Disable Schema Version 1 templates immediately',
          'Restrict EKU specification in certificate templates',
          'Implement strict certificate template validation',
          'Use Locksmith to identify and remediate ESC15 vulnerabilities',
          'Monitor certificate requests with suspicious EKU values',
          'Implement certificate template schema version validation',
          'Regular AD CS security assessments and template auditing',
          'Configure certificate template restrictions in Group Policy',
          'Enable certificate issuance monitoring and alerting for Schema V1 templates'
        ],
        windowsEvents: ['4887 (Certificate Issued)', '54 (Certificate Issued)', '4898 (Certificate Template Permissions Changed)', '4899 (Certificate Template Updated)', '4900 (Certificate Services Template Loaded)', '4886 (Certificate Services Started)', '4888 (Certificate Services Backup Started)', '4909 (Certificate Services Template Settings Changed)', '4910 (Certificate Services Template Updated)', '53 (Certificate Request)', '4876 (Certificate Services Backup Started)', '4877 (Certificate Services Backup Completed)'],
        exampleQuery: `index=windows EventCode=4887 | stats count by CertificateTemplate, SchemaVersion | where SchemaVersion=1`,
        recommendedThresholds: {
          schemaV1Bonus: 3,
          arbitraryEKUBonus: 2,
          clientAuthEKUBonus: 1,
          minVulnerableTemplates: 1
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    const adcsContext = context as ADCSContext

    // Check certificate templates for Schema V1 vulnerabilities
    const templateAnomalies = this.analyzeCertificateTemplates(adcsContext)
    anomalies.push(...templateAnomalies)

    // Analyze certificate requests using Schema V1 templates
    const certificateEvents = events.filter(event =>
      this.isCertificateEvent(event)
    ) as CertificateEvent[]

    if (certificateEvents.length > 0) {
      const requestAnomalies = this.analyzeSchemaV1Requests(certificateEvents, adcsContext)
      anomalies.push(...requestAnomalies)
    }

    return anomalies
  }

  private isCertificateEvent(event: AuthEvent): boolean {
    const adcsEventIds = ['4886', '4887', '4888', '53', '54']
    return adcsEventIds.includes(event.eventId) ||
           (event as CertificateEvent).certificateTemplate !== undefined
  }

  private analyzeCertificateTemplates(context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    if (!context.certificateTemplates) return anomalies

    const schemaV1Templates = context.certificateTemplates.filter(template =>
      template.schemaVersion === 1 && template.enabled
    )

    if (schemaV1Templates.length >= this.thresholds.minVulnerableTemplates) {
      schemaV1Templates.forEach(template => {
        let riskScore = 3 // Base high risk for Schema V1
        let confidence = 95

        // Schema V1 is inherently vulnerable
        riskScore += this.thresholds.schemaV1Bonus

        // Check if template allows arbitrary EKUs (makes it more dangerous)
        const allowsArbitraryEKUs = this.templateAllowsArbitraryEKUs(template)
        if (allowsArbitraryEKUs) {
          riskScore += this.thresholds.arbitraryEKUBonus
          confidence += 5
        }

        // Check if template has client authentication EKU
        const hasClientAuthEKU = template.extendedKeyUsage?.some(eku =>
          ['1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2'].includes(eku)
        )
        if (hasClientAuthEKU) {
          riskScore += this.thresholds.clientAuthEKUBonus
          confidence += 5
        }

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

        // Ensure risk score doesn't exceed critical
        riskScore = Math.min(riskScore, 5)

        const detection: ESCDetectionResult = {
          vulnerability: 'ESC15',
          severity: 'critical',
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
            schemaVersion: template.schemaVersion,
            enrollmentFlags: template.enrollmentFlags,
            certificateNameFlags: template.certificateNameFlags,
            extendedKeyUsage: template.extendedKeyUsage,
            allowsArbitraryEKUs,
            hasClientAuthEKU,
            hasManagerApproval,
            accessibleByLargeGroups,
            cve: 'CVE-2024-49019',
            vulnerabilityName: 'EKUwu',
            templatePermissions: template.permissions,
            riskFactors: [
              'Schema Version 1 (vulnerable to CVE-2024-49019)',
              ...(allowsArbitraryEKUs ? ['Allows arbitrary EKUs'] : []),
              ...(hasClientAuthEKU ? ['Client authentication enabled'] : []),
              ...(!hasManagerApproval ? ['No manager approval required'] : []),
              ...(accessibleByLargeGroups ? ['Accessible by large groups'] : [])
            ]
          },
          remediation: [
            'Upgrade certificate template to Schema Version 2',
            'Enable Manager Approval for the template',
            'Restrict template permissions to specific users/groups',
            'Monitor for EKUwu exploitation attempts',
            'Consider disabling Schema V1 templates',
            'Apply Microsoft security updates for CVE-2024-49019',
            'Use the Unpublish-SchemaV1Templates.ps1 script if needed'
          ]
        }

        const anomaly = this.createESC15Anomaly(detection, context)
        anomalies.push(anomaly)
      })
    }

    return anomalies
  }

  private analyzeSchemaV1Requests(events: CertificateEvent[], context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    // Find requests using Schema V1 templates
    const schemaV1Requests = events.filter(event => {
      if (!event.certificateTemplate) return false

      // Check if this template is Schema V1
      const template = context.certificateTemplates?.find(t =>
        t.name === event.certificateTemplate || t.displayName === event.certificateTemplate
      )

      return template?.schemaVersion === 1 && event.status === 'Success'
    })

    if (schemaV1Requests.length > 0) {
      // Group by template
      const templateGroups = this.groupByTemplate(schemaV1Requests)

      Object.entries(templateGroups).forEach(([templateName, templateEvents]) => {
        const template = context.certificateTemplates?.find(t =>
          t.name === templateName || t.displayName === templateName
        )

        if (!template) return

        let riskScore = 4 // High risk for actual usage
        let confidence = 90

        // Check for suspicious EKU usage in the issued certificates
        const suspiciousEKUs = templateEvents.filter(event => {
          const ekus = event.extendedKeyUsage || []
          return ekus.some(eku => this.isSuspiciousEKU(eku))
        })

        if (suspiciousEKUs.length > 0) {
          riskScore += 1
          confidence += 10
        }

        // Check if certificates were issued to privileged users
        const privilegedUsers = templateEvents.filter(event => {
          const userProfile = context.userProfiles?.find(u =>
            u.userName === event.userName && u.domain === event.domainName
          )
          return userProfile?.privileged
        })

        if (privilegedUsers.length > 0) {
          riskScore += 1
          confidence += 15
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'ESC15',
          severity: 'critical',
          confidence: Math.min(confidence, 100),
          affectedEntities: [
            {
              type: 'certificateTemplate',
              id: templateName,
              name: template.displayName || template.name
            }
          ],
          evidence: {
            templateName,
            schemaVersion: template.schemaVersion,
            totalRequests: templateEvents.length,
            successfulRequests: templateEvents.length,
            suspiciousEKUs: suspiciousEKUs.length,
            privilegedUsers: privilegedUsers.length,
            cve: 'CVE-2024-49019',
            vulnerabilityName: 'EKUwu',
            issuedCertificates: templateEvents.map(event => ({
              requestId: event.requestId,
              userName: event.userName,
              timestamp: event.timestamp,
              serialNumber: event.serialNumber,
              thumbprint: event.thumbprint,
              extendedKeyUsage: event.extendedKeyUsage
            })),
            riskFactors: [
              'Schema V1 template actively used',
              ...(suspiciousEKUs.length > 0 ? [`${suspiciousEKUs.length} certificates with suspicious EKUs`] : []),
              ...(privilegedUsers.length > 0 ? [`${privilegedUsers.length} certificates issued to privileged users`] : [])
            ]
          },
          remediation: [
            'Immediately disable the Schema V1 template',
            'Revoke any certificates issued from this template',
            'Upgrade to Schema V2 template',
            'Enable Manager Approval for replacement template',
            'Monitor for privilege escalation using issued certificates',
            'Audit all authentication events using these certificates'
          ]
        }

        const anomaly = this.createESC15Anomaly(detection, context)
        anomalies.push(anomaly)
      })
    }

    return anomalies
  }

  private templateAllowsArbitraryEKUs(template: any): boolean {
    // Check if template allows arbitrary EKU specification
    // This could be indicated by:
    // 1. No specific EKUs defined
    // 2. Any Purpose EKU present
    // 3. Specific flags that allow EKU modification

    const hasNoEKUs = !template.extendedKeyUsage || template.extendedKeyUsage.length === 0
    const hasAnyPurposeEKU = template.extendedKeyUsage?.includes('2.5.29.37.0')

    return hasNoEKUs || hasAnyPurposeEKU
  }

  private isSuspiciousEKU(eku: string): boolean {
    // EKUs that might indicate EKUwu exploitation
    const suspiciousEKUs = [
      '1.3.6.1.4.1.311.10.3.13', // KDC Authentication (uncommon)
      '1.3.6.1.5.5.7.3.9',       // OCSP Signing (uncommon for users)
      '1.3.6.1.4.1.311.10.3.4',  // Encrypting File System (uncommon)
      '2.5.29.37.0'              // Any Purpose
    ]

    return suspiciousEKUs.includes(eku)
  }

  private isAccessibleByLargeGroups(template: any): boolean {
    // Check if template permissions allow access by large groups
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

  private createESC15Anomaly(
    detection: ESCDetectionResult,
    context: ADCSContext
  ): Anomaly {
    const title = `🚨 ESC15/EKUwu Vulnerability: ${detection.affectedEntities[0].name}`
    const description = `Schema Version 1 certificate template ${detection.affectedEntities[0].name} is vulnerable to CVE-2024-49019 (EKUwu). ` +
      `Attackers can request certificates with arbitrary EKUs for privilege escalation.`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: detection.vulnerability,
        severity: detection.severity,
        confidence: detection.confidence,
        templateName: detection.affectedEntities[0].name,
        cve: detection.evidence.cve,
        vulnerabilityName: detection.evidence.vulnerabilityName,
        timeWindow: this.timeWindow,
        detectionMethod: 'certificate_template_analysis',
        evidence: detection.evidence
      },
      detection.confidence,
      {
        attackType: 'eku_manipulation_exploit',
        vulnerabilityType: 'ESC15',
        riskLevel: detection.severity,
        cve: 'CVE-2024-49019'
      }
    )
  }
}
