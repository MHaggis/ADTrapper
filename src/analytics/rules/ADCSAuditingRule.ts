import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, ADCSContext, ESCDetectionResult } from '../types'

export class ADCSAuditingRule extends BaseRule {
  // Required audit filter value for full auditing (127 = 0x7F)
  private readonly FULL_AUDIT_FILTER = 127

  constructor() {
    super({
      id: 'adcs_auditing_detection',
      name: 'AD CS Auditing Configuration Detection',
      description: 'Detects inadequate AD CS auditing configuration that could hide attack activities',
      category: 'security',
      severity: 'medium',
      timeWindow: 1440, // 24 hours for auditing analysis
      thresholds: {
        auditFilterThreshold: 127,
        missingEventsBonus: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects inadequate Active Directory Certificate Services (AD CS) auditing configuration that could allow attackers to operate undetected. Proper AD CS auditing is critical for detecting certificate-based attacks, template modifications, and CA compromise activities.',
        detectionLogic: 'Analyzes Certificate Authority audit filter configurations and checks for missing critical audit events. Validates that all AD CS operations are properly logged, including certificate requests, issuances, revocations, template modifications, and CA management activities.',
        falsePositives: 'This is a configuration assessment rule that evaluates audit settings rather than runtime behavior. It will trigger on any CA that does not have full auditing enabled, which is a security configuration issue rather than an active attack.',
        mitigation: [
          'Enable full AD CS auditing on all Certificate Authorities',
          'Configure audit filter to value 127 (0x7F) for complete auditing',
          'Enable object access auditing for PKI containers and templates',
          'Monitor Windows Security event logs for AD CS events',
          'Implement centralized log collection and analysis',
          'Regular audit configuration verification',
          'Use Group Policy to enforce AD CS auditing settings',
          'Enable advanced auditing for certificate services',
          'Configure AD CS event forwarding to SIEM systems',
          'Regular security assessment of PKI infrastructure'
        ],
        windowsEvents: ['4886 (Certificate Services Started)', '4887 (Certificate Services Stopped)', '4888 (Certificate Services Backup Started)', '4889 (Certificate Services Restore Started)', '4890 (Certificate Services Backup Completed)', '4891 (Certificate Services Restore Completed)', '4898 (Certificate Template Loaded)', '4899 (Certificate Template Updated)', '53 (Certificate Request)', '54 (Certificate Issued)', '55 (Certificate Request Denied)', '56 (Certificate Revoked)'],
        exampleQuery: `index=windows EventCode=4886 OR EventCode=4887 | stats count by Computer | where count < 2`,
        recommendedThresholds: {
          auditFilterThreshold: 127,
          missingEventsBonus: 1
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    const adcsContext = context as ADCSContext

    // Check CA auditing configuration
    const caAuditingAnomalies = this.analyzeCAAuditing(adcsContext)
    anomalies.push(...caAuditingAnomalies)

    // Check for missing critical audit events
    const missingEventsAnomalies = this.analyzeMissingAuditEvents(events, adcsContext)
    anomalies.push(...missingEventsAnomalies)

    return anomalies
  }

  private analyzeCAAuditing(context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    if (!context.certificateAuthorities) return anomalies

    context.certificateAuthorities.forEach(ca => {
      const auditFilter = ca.auditFilter

      if (auditFilter !== this.FULL_AUDIT_FILTER) {
        let riskScore = 2 // Base medium risk
        let confidence = 90

        // Calculate what's missing from full auditing
        const missingAudits = this.identifyMissingAudits(auditFilter)
        if (missingAudits.length > 0) {
          riskScore += this.thresholds.missingEventsBonus
          confidence += 5
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'Auditing' as any,
          severity: riskScore >= 3 ? 'medium' : 'low',
          confidence,
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
            currentAuditFilter: auditFilter,
            requiredAuditFilter: this.FULL_AUDIT_FILTER,
            missingAudits,
            auditFilterHex: `0x${auditFilter.toString(16).toUpperCase()}`,
            isFullAuditingEnabled: auditFilter === this.FULL_AUDIT_FILTER,
            caConfiguration: {
              interfaceFlags: ca.interfaceFlags,
              editFlags: ca.editFlags,
              securityFlags: ca.securityFlags
            }
          },
          remediation: [
            `Enable full auditing on CA: ${ca.name}`,
            'Run: certutil -config "CAHostName\\CAName" -setreg CA\\AuditFilter 127',
            'Restart Certificate Services after changing audit settings',
            'Verify auditing is working by checking Security event logs',
            'Enable object access auditing in Group Policy for PKI objects',
            'Monitor for certificate-related security events'
          ]
        }

        const anomaly = this.createAuditingAnomaly(detection, context)
        anomalies.push(anomaly)
      }
    })

    return anomalies
  }

  private analyzeMissingAuditEvents(events: AuthEvent[], context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    // Check if we have the expected ADCS audit events
    const adcsEvents = events.filter(event =>
      this.isADCSEvent(event)
    )

    if (adcsEvents.length === 0) {
      // No ADCS events found - could indicate missing auditing
      const detection: ESCDetectionResult = {
        vulnerability: 'Auditing' as any,
        severity: 'medium',
        confidence: 70,
        affectedEntities: [],
        evidence: {
          totalEvents: events.length,
          adcsEvents: adcsEvents.length,
          timeWindow: this.timeWindow,
          possibleMissingAuditing: true,
          expectedEvents: [
            '4886 - Certificate request received',
            '4887 - Certificate issued',
            '4888 - Certificate request denied',
            '4898 - Certificate template permissions changed',
            '4899 - Certificate template updated'
          ]
        },
        remediation: [
          'Verify AD CS auditing is properly configured on all Certificate Authorities',
          'Check that AuditFilter is set to 127 (0x7F) on all CAs',
          'Enable "Audit Certification Services" in Advanced Audit Policy',
          'Ensure Security event log has sufficient space for audit events',
          'Review Group Policy settings for object access auditing'
        ]
      }

      const anomaly = this.createAuditingAnomaly(detection, context)
      anomalies.push(anomaly)
    }

    return anomalies
  }

  private isADCSEvent(event: AuthEvent): boolean {
    const adcsEventIds = [
      '4886', '4887', '4888', '4898', '4899', '4900',
      '53', '54', '5136', '5137', '5141'
    ]
    return adcsEventIds.includes(event.eventId)
  }

  private identifyMissingAudits(currentFilter: number): string[] {
    const missingAudits: string[] = []

    // Check individual audit flags (based on Windows CA audit filter values)
    const auditFlags = [
      { value: 1, description: 'Audit certificate requests' },
      { value: 2, description: 'Audit certificate requests denied' },
      { value: 4, description: 'Audit certificates issued' },
      { value: 8, description: 'Audit certificate revocation' },
      { value: 16, description: 'Audit CA certificate changed' },
      { value: 32, description: 'Audit security permissions changed' },
      { value: 64, description: 'Audit backup/restore operations' }
    ]

    auditFlags.forEach(flag => {
      if ((currentFilter & flag.value) === 0) {
        missingAudits.push(flag.description)
      }
    })

    return missingAudits
  }

  private createAuditingAnomaly(
    detection: ESCDetectionResult,
    context: ADCSContext
  ): Anomaly {
    const title = `⚠️ AD CS Auditing Issue${detection.affectedEntities.length > 0 ? `: ${detection.affectedEntities[0].name}` : ''}`
    const description = detection.affectedEntities.length > 0
      ? `Certificate Authority ${detection.affectedEntities[0].name} does not have full auditing enabled. ` +
        `This could allow attacks to go undetected.`
      : `No AD CS audit events detected in the time window. ` +
        `This may indicate inadequate auditing configuration.`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: detection.vulnerability,
        severity: detection.severity,
        confidence: detection.confidence,
        affectedEntity: detection.affectedEntities.length > 0 ? detection.affectedEntities[0].name : 'All CAs',
        timeWindow: this.timeWindow,
        detectionMethod: 'auditing_configuration_analysis',
        evidence: detection.evidence
      },
      detection.confidence,
      {
        attackType: 'auditing_bypass',
        vulnerabilityType: 'Auditing',
        riskLevel: detection.severity
      }
    )
  }
}
