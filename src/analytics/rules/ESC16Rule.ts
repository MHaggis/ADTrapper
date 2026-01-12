import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, CertificateEvent, ADCSContext, ESCDetectionResult } from '../types'

export class ESC16Rule extends BaseRule {
  // szOID_NTDS_CA_SECURITY_EXT OID
  private readonly NTDS_CA_SECURITY_EXT_OID = '1.3.6.1.4.1.311.25.2'

  constructor() {
    super({
      id: 'esc16_ca_security_extension_disabled',
      name: 'ESC16 - CA-Level Security Extension Disabled',
      description: 'Detects when Certificate Authority has szOID_NTDS_CA_SECURITY_EXT extension disabled',
      category: 'security',
      severity: 'medium',
      timeWindow: 120, // 2 hours for CA configuration analysis
      thresholds: {
        caLevelDisableBonus: 2,
        vulnerableTemplatesBonus: 1,
        multipleCAsBonus: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects ESC16 vulnerabilities where Certificate Authorities (CAs) have the szOID_NTDS_CA_SECURITY_EXT extension disabled, affecting all certificates issued by that CA. While less critical than template-level issues, CA-level security extension disablement reduces the overall security posture of the PKI infrastructure.',
        detectionLogic: 'Analyzes CA configurations for disabled szOID_NTDS_CA_SECURITY_EXT extension and monitors certificate issuances from vulnerable CAs. Identifies CAs where the security extension has been disabled at the authority level, potentially affecting multiple certificate templates and issuances.',
        falsePositives: 'Legitimate CA configurations where security extensions are intentionally disabled for compatibility reasons, certificate requests that follow organizational security policies, or CA configurations that have been reviewed and approved for specific use cases. May also trigger during legitimate CA maintenance or configuration changes.',
        mitigation: [
          'Enable szOID_NTDS_CA_SECURITY_EXT extension on vulnerable Certificate Authorities',
          'Configure CA security settings to include security extensions',
          'Review and validate CA configuration settings',
          'Implement CA security extension validation',
          'Use Locksmith to identify and remediate ESC16 vulnerabilities',
          'Monitor certificate issuances from CAs with disabled security extensions',
          'Implement CA configuration auditing and compliance checking',
          'Regular AD CS security assessments and CA configuration auditing',
          'Configure CA security restrictions in Group Policy',
          'Enable CA security extension monitoring and alerting'
        ],
        windowsEvents: ['4886 (Certificate Services Started)', '4887 (Certificate Issued)', '4888 (Certificate Services Backup Started)', '4890 (Certificate Services Restore Completed)', '4900 (Certificate Services Template Loaded)', '4909 (Certificate Services Template Settings Changed)', '4910 (Certificate Services Template Updated)', '4876 (Certificate Services Backup Started)', '4877 (Certificate Services Backup Completed)'],
        exampleQuery: `index=windows EventCode=4887 | stats count by CertificateAuthority, HasSecurityExtension | where HasSecurityExtension="false"`,
        recommendedThresholds: {
          caLevelDisableBonus: 2,
          vulnerableTemplatesBonus: 1,
          multipleCAsBonus: 1
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    const adcsContext = context as ADCSContext

    // Analyze CA configuration for disabled security extensions
    const caConfigurationAnomalies = this.analyzeCAConfiguration(adcsContext)
    anomalies.push(...caConfigurationAnomalies)

    // Analyze certificate issuances that might be affected
    const certificateEvents = events.filter(event =>
      this.isCertificateEvent(event)
    ) as CertificateEvent[]

    if (certificateEvents.length > 0) {
      const issuanceAnomalies = this.analyzeCertificateIssuances(certificateEvents, adcsContext)
      anomalies.push(...issuanceAnomalies)
    }

    return anomalies
  }

  private isCertificateEvent(event: AuthEvent): boolean {
    const certEventIds = ['4887', '54'] // Certificate issued events
    return certEventIds.includes(event.eventId) ||
           (event as CertificateEvent).certificateTemplate !== undefined
  }

  private analyzeCAConfiguration(context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    if (!context.certificateAuthorities) return anomalies

    const vulnerableCAs = context.certificateAuthorities.filter(ca => {
      // Check if CA has the security extension disabled
      return this.hasSecurityExtensionDisabled(ca)
    })

    vulnerableCAs.forEach(ca => {
      let riskScore = 2 // Base medium risk for CA-level security issues
      let confidence = 80

      // CA-level disable is more serious than template-level
      riskScore += this.thresholds.caLevelDisableBonus

      // Check if CA has vulnerable templates
      const vulnerableTemplates = this.getVulnerableTemplates(ca, context)
      if (vulnerableTemplates.length > 0) {
        riskScore += this.thresholds.vulnerableTemplatesBonus
        confidence += 15
      }

      // Check if CA has proper auditing
      const hasFullAuditing = (ca.auditFilter || 0) === 127
      if (!hasFullAuditing) {
        riskScore += 1
        confidence += 10
      }

      // Check if multiple CAs are vulnerable
      if (vulnerableCAs.length > 1) {
        riskScore += this.thresholds.multipleCAsBonus
        confidence += 5
      }

      const detection: ESCDetectionResult = {
        vulnerability: 'ESC16',
        severity: riskScore >= 4 ? 'high' : riskScore >= 3 ? 'medium' : 'low',
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
          securityFlags: ca.securityFlags,
          interfaceFlags: ca.interfaceFlags,
          auditFilter: ca.auditFilter,
          hasSecurityExtensionDisabled: true,
          disabledExtension: this.NTDS_CA_SECURITY_EXT_OID,
          vulnerableTemplates: vulnerableTemplates.length,
          templateNames: vulnerableTemplates.map(t => t.name),
          hasFullAuditing,
          caConfiguration: {
            editFlags: ca.editFlags,
            templates: ca.templates
          }
        },
        remediation: [
          `Enable szOID_NTDS_CA_SECURITY_EXT extension on CA: ${ca.name}`,
          'Update CA security configuration to include strong certificate binding',
          'Restart Certificate Services after configuration change',
          'Review and fix vulnerable certificate templates',
          'Enable full CA auditing (AuditFilter = 127)',
          'Monitor certificate issuances for security extension compliance'
        ]
      }

      const anomaly = this.createESC16Anomaly(detection, context)
      anomalies.push(anomaly)
    })

    return anomalies
  }

  private analyzeCertificateIssuances(events: CertificateEvent[], context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    // Find CAs with disabled security extensions
    const vulnerableCAs = context.certificateAuthorities?.filter(ca =>
      this.hasSecurityExtensionDisabled(ca)
    ) || []

    if (vulnerableCAs.length === 0) return anomalies

    // Look for certificates issued by vulnerable CAs
    const vulnerableCAIssuances = events.filter(event => {
      if (event.status !== 'Success') return false

      // Check if certificate was issued by a vulnerable CA
      return vulnerableCAs.some(ca =>
        ca.name === event.certificateAuthority ||
        ca.dnsName === event.certificateAuthority
      )
    })

    if (vulnerableCAIssuances.length > 0) {
      // Group by CA
      const caGroups = this.groupByCA(vulnerableCAIssuances)

      Object.entries(caGroups).forEach(([caName, caEvents]) => {
        const ca = vulnerableCAs.find(c => c.name === caName || c.dnsName === caName)
        if (!ca) return

        let riskScore = 3 // Base high risk for actual issuances
        let confidence = 85

        // Check if certificates have client authentication EKU
        const clientAuthCertificates = caEvents.filter(event =>
          event.extendedKeyUsage?.some(eku =>
            ['1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2'].includes(eku)
          )
        )

        if (clientAuthCertificates.length > 0) {
          riskScore += 1
          confidence += 15
        }

        // Check if certificates were issued to privileged users
        const privilegedUsers = caEvents.filter(event => {
          const userProfile = context.userProfiles?.find(u =>
            u.userName === event.userName && u.domain === event.domainName
          )
          return userProfile?.privileged
        })

        if (privilegedUsers.length > 0) {
          riskScore += 1
          confidence += 10
        }

        // Check for multiple issuances
        if (caEvents.length > 10) {
          riskScore += 1
          confidence += 10
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'ESC16',
          severity: riskScore >= 5 ? 'critical' : riskScore >= 4 ? 'high' : 'medium',
          confidence: Math.min(confidence, 100),
          affectedEntities: [
            {
              type: 'certificateAuthority',
              id: ca.name,
              name: ca.displayName || ca.name
            },
            ...Array.from(new Set(caEvents.map(e => e.userName).filter(Boolean))).slice(0, 3).map(user => ({
              type: 'user' as const,
              id: user as string,
              name: user as string
            }))
          ],
          evidence: {
            caName: ca.name,
            vulnerableIssuances: caEvents.length,
            clientAuthCertificates: clientAuthCertificates.length,
            privilegedUsers: privilegedUsers.length,
            totalAffectedUsers: new Set(caEvents.map(e => e.userName).filter(Boolean)).size,
            hasSecurityExtensionDisabled: true,
            disabledExtension: this.NTDS_CA_SECURITY_EXT_OID,
            certificates: caEvents.slice(0, 10).map(event => ({
              requestId: event.requestId,
              userName: event.userName,
              template: event.certificateTemplate,
              serialNumber: event.serialNumber,
              timestamp: event.timestamp,
              hasClientAuthEKU: clientAuthCertificates.some(c => c.requestId === event.requestId)
            })),
            caConfiguration: {
              securityFlags: ca.securityFlags,
              auditFilter: ca.auditFilter
            }
          },
          remediation: [
            'Immediately revoke certificates issued by vulnerable CA',
            'Enable szOID_NTDS_CA_SECURITY_EXT extension on the CA',
            'Update CA configuration for strong certificate binding',
            'Restart Certificate Services',
            'Re-issue certificates with proper security extensions',
            'Monitor authentication using revoked certificates',
            'Implement CA security extension validation'
          ]
        }

        const anomaly = this.createESC16Anomaly(detection, context)
        anomalies.push(anomaly)
      })
    }

    return anomalies
  }

  private hasSecurityExtensionDisabled(ca: any): boolean {
    // Check CA configuration for disabled security extension
    // This would typically check the CA's security settings or registry
    const securityFlags = ca.securityFlags || 0
    const interfaceFlags = ca.interfaceFlags || 0

    // Check for flags that indicate the security extension is disabled
    // This is a simplified check - in reality, we'd check specific CA configuration
    return (securityFlags & 0x00000001) === 0 ||
           (interfaceFlags & 0x00000002) === 0
  }

  private getVulnerableTemplates(ca: any, context: ADCSContext): any[] {
    if (!context.certificateTemplates || !ca.templates) return []

    return context.certificateTemplates.filter(template => {
      // Check if template is enabled on this CA
      const enabledOnCA = ca.templates.includes(template.name)
      if (!enabledOnCA) return false

      // Check if template has client authentication and no manager approval
      const hasClientAuthEKU = template.extendedKeyUsage?.some(eku =>
        ['1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2'].includes(eku)
      )
      const hasManagerApproval = (template.enrollmentFlags & 2) !== 0

      return template.enabled && hasClientAuthEKU && !hasManagerApproval
    })
  }

  private groupByCA(events: CertificateEvent[]): Record<string, CertificateEvent[]> {
    const groups: Record<string, CertificateEvent[]> = {}

    events.forEach(event => {
      const caName = event.certificateAuthority || event.rawData?.certificateAuthority || 'Unknown'
      if (!groups[caName]) {
        groups[caName] = []
      }
      groups[caName].push(event)
    })

    return groups
  }

  private createESC16Anomaly(
    detection: ESCDetectionResult,
    context: ADCSContext
  ): Anomaly {
    const title = `🚨 ESC16 Vulnerability: CA Security Extension Disabled`
    const description = `Certificate Authority ${detection.affectedEntities[0].name} has the szOID_NTDS_CA_SECURITY_EXT extension disabled. ` +
      `This allows certificates to be issued without strong binding controls, enabling privilege escalation attacks.`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: detection.vulnerability,
        severity: detection.severity,
        confidence: detection.confidence,
        caName: detection.affectedEntities[0].name,
        timeWindow: this.timeWindow,
        detectionMethod: 'ca_security_analysis',
        evidence: detection.evidence
      },
      detection.confidence,
      {
        attackType: 'ca_security_extension_disabled',
        vulnerabilityType: 'ESC16',
        riskLevel: detection.severity
      }
    )
  }
}
