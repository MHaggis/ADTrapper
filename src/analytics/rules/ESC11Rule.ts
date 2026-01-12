import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, CertificateEvent, ADCSContext, ESCDetectionResult } from '../types'

export class ESC11Rule extends BaseRule {
  // IF_ENFORCEENCRYPTICERTREQUEST flag
  private readonly IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200

  constructor() {
    super({
      id: 'esc11_unencrypted_requests_detection',
      name: 'ESC11 - Unencrypted Certificate Requests Detection',
      description: 'Detects unencrypted certificate requests that are vulnerable to NTLM relay attacks',
      category: 'security',
      severity: 'medium',
      timeWindow: 60, // 1 hour for request analysis
      thresholds: {
        unencryptedRequestsThreshold: 1,
        ntlmRelayBonus: 2,
        rpcInterfaceBonus: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects ESC11 vulnerabilities where Certificate Authority (CA) configurations do not enforce encrypted certificate requests, making RPC-based enrollment vulnerable to NTLM relay attacks. Without the IF_ENFORCEENCRYPTICERTREQUEST flag, certificate requests can be intercepted and relayed to obtain certificates for other users.',
        detectionLogic: 'Analyzes CA interface flags for the IF_ENFORCEENCRYPTICERTREQUEST (0x00000200) setting and monitors certificate requests for unencrypted patterns. Detects RPC certificate enrollment without encryption enforcement and identifies NTLM authentication usage that increases relay attack risk.',
        falsePositives: 'Legitimate RPC certificate requests in secure internal networks, certificate requests that use proper encryption, or enrollment processes that follow organizational security policies. May also trigger during legitimate certificate renewal or system administration activities.',
        mitigation: [
          'Enable IF_ENFORCEENCRYPTICERTREQUEST flag on Certificate Authorities',
          'Configure CA to enforce encrypted certificate requests',
          'Disable unencrypted RPC certificate enrollment',
          'Implement certificate request encryption for all enrollment methods',
          'Monitor unencrypted certificate request attempts',
          'Use Locksmith to identify and remediate ESC11 vulnerabilities',
          'Configure CA interface flags for enhanced security',
          'Implement network-level protection against NTLM relay attacks',
          'Regular AD CS security assessments and configuration audits',
          'Configure certificate enrollment encryption requirements'
        ],
        windowsEvents: ['4886 (Certificate Services Started)', '4887 (Certificate Issued)', '4888 (Certificate Services Backup Started)', '53 (Certificate Request)', '54 (Certificate Issued)', '4876 (Certificate Services Backup Started)', '4877 (Certificate Services Backup Completed)', '4624 (Account Logon)', '4625 (Account Logon Failed)', '4776 (NTLM Authentication)', '5140 (Network Share Access)', '5145 (Network Share Object Access)'],
        exampleQuery: `index=windows EventCode=4887 | stats count by Protocol, EncryptionUsed | where EncryptionUsed="false"`,
        recommendedThresholds: {
          unencryptedRequestsThreshold: 1,
          ntlmRelayBonus: 2,
          rpcInterfaceBonus: 1
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    const adcsContext = context as ADCSContext

    // Check CA configuration for IF_ENFORCEENCRYPTICERTREQUEST flag
    const caConfigurationAnomalies = this.analyzeCAInterfaceFlags(adcsContext)
    anomalies.push(...caConfigurationAnomalies)

    // Analyze certificate requests for unencrypted patterns
    const certificateEvents = events.filter(event =>
      this.isCertificateEvent(event)
    ) as CertificateEvent[]

    if (certificateEvents.length > 0) {
      const unencryptedRequestAnomalies = this.analyzeUnencryptedRequests(certificateEvents, adcsContext)
      anomalies.push(...unencryptedRequestAnomalies)
    }

    return anomalies
  }

  private isCertificateEvent(event: AuthEvent): boolean {
    const adcsEventIds = ['4886', '4887', '4888', '53', '54']
    return adcsEventIds.includes(event.eventId) ||
           (event as CertificateEvent).certificateTemplate !== undefined
  }

  private analyzeCAInterfaceFlags(context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    if (!context.certificateAuthorities) return anomalies

    context.certificateAuthorities.forEach(ca => {
      // Check if IF_ENFORCEENCRYPTICERTREQUEST flag is missing
      const hasEnforceEncryptionFlag = (ca.interfaceFlags & this.IF_ENFORCEENCRYPTICERTREQUEST) !== 0

      if (!hasEnforceEncryptionFlag) {
        let riskScore = 2 // Base low risk
        let confidence = 85

        // Check if RPC interface is enabled (increases risk)
        const rpcInterfaceEnabled = (ca.interfaceFlags & 0x00000001) !== 0
        if (rpcInterfaceEnabled) {
          riskScore += this.thresholds.rpcInterfaceBonus
          confidence += 15
        }

        // Check for NTLM authentication patterns
        const usesNTLM = this.detectNTLMUsage(ca, context)
        if (usesNTLM) {
          riskScore += this.thresholds.ntlmRelayBonus
          confidence += 20
        }

        // Check if CA has vulnerable templates that could be exploited
        const vulnerableTemplates = this.findVulnerableTemplates(context)
        if (vulnerableTemplates.length > 0) {
          riskScore += 1
          confidence += 10
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'ESC11',
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
            interfaceFlags: ca.interfaceFlags,
            hasIF_ENFORCEENCRYPTICERTREQUEST: hasEnforceEncryptionFlag,
            rpcInterfaceEnabled,
            usesNTLM,
            vulnerableTemplates: vulnerableTemplates.length,
            templateNames: vulnerableTemplates.map(t => t.name),
            caConfiguration: {
              auditFilter: ca.auditFilter,
              editFlags: ca.editFlags,
              securityFlags: ca.securityFlags
            }
          },
          remediation: [
            `Enable IF_ENFORCEENCRYPTICERTREQUEST flag on CA: ${ca.name}`,
            'Run: certutil -config "CAHostName\\CAName" -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST',
            'Restart Certificate Services after flag change',
            'Consider disabling RPC certificate requests if not required',
            'Implement network-level encryption for certificate communications',
            'Use HTTPS for web enrollment instead of RPC'
          ]
        }

        const anomaly = this.createESC11Anomaly(detection, context)
        anomalies.push(anomaly)
      }
    })

    return anomalies
  }

  private analyzeUnencryptedRequests(events: CertificateEvent[], context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    // Look for events that indicate unencrypted certificate requests
    const unencryptedEvents = events.filter(event => {
      // Check for RPC-based requests without encryption
      return event.rawData?.protocol === 'rpc' ||
             event.rawData?.encryption === false ||
             event.rawData?.interface === 'rpc' ||
             event.requestType === 'rpc_request'
    })

    if (unencryptedEvents.length >= this.thresholds.unencryptedRequestsThreshold) {
      // Group by source IP
      const sourceGroups = this.groupBySourceIP(unencryptedEvents)

      Object.entries(sourceGroups).forEach(([sourceIP, sourceEvents]) => {
        let riskScore = 1 // Base very low risk for detected unencrypted requests
        let confidence = 75

        // Check if source IP is suspicious
        const ipInfo = context.ipIntelligence?.find(ip => ip.ip === sourceIP)
        const isSuspiciousSource = ipInfo && (
          ipInfo.isTor || ipInfo.isVpn || ipInfo.isMalicious || ipInfo.riskScore > 70
        )

        if (isSuspiciousSource) {
          riskScore += 1
          confidence += 15
        }

        // Check if CA has the encryption enforcement flag disabled
        const ca = this.findCAForEvents(sourceEvents, context)
        const hasEncryptionFlag = ca ? (ca.interfaceFlags & this.IF_ENFORCEENCRYPTICERTREQUEST) !== 0 : true

        if (!hasEncryptionFlag) {
          riskScore += this.thresholds.ntlmRelayBonus
          confidence += 25
        }

        // Check for NTLM authentication in the requests
        const usesNTLM = sourceEvents.some(event =>
          event.authenticationPackage === 'NTLM' ||
          event.rawData?.authPackage === 'NTLM'
        )

        if (usesNTLM) {
          riskScore += this.thresholds.ntlmRelayBonus
          confidence += 20
        }

        if (sourceEvents.length > 5) {
          riskScore += 1
          confidence += 10
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'ESC11',
          severity: riskScore >= 4 ? 'high' : riskScore >= 3 ? 'medium' : 'low',
          confidence: Math.min(confidence, 100),
          affectedEntities: [
            {
              type: 'ip',
              id: sourceIP,
              name: sourceIP
            },
            ...(ca ? [{
              type: 'certificateAuthority' as const,
              id: ca.name,
              name: ca.displayName || ca.name
            }] : [])
          ],
          evidence: {
            sourceIP,
            unencryptedRequests: sourceEvents.length,
            isSuspiciousSource,
            ipIntelligence: ipInfo,
            caHasEncryptionFlag: hasEncryptionFlag,
            usesNTLM,
            protocols: Array.from(new Set(sourceEvents.map(e => e.rawData?.protocol || 'rpc'))),
            certificateTemplates: Array.from(new Set(sourceEvents.map(e => e.certificateTemplate).filter(Boolean))),
            sampleRequests: sourceEvents.slice(0, 5).map(event => ({
              timestamp: event.timestamp,
              userName: event.userName,
              template: event.certificateTemplate,
              protocol: event.rawData?.protocol || 'rpc',
              authPackage: event.authenticationPackage || event.rawData?.authPackage
            }))
          },
          remediation: [
            'Enable IF_ENFORCEENCRYPTICERTREQUEST flag on the Certificate Authority',
            'Use HTTPS for web enrollment instead of RPC',
            'Implement network-level encryption (IPsec) for certificate communications',
            'Avoid NTLM authentication for certificate requests',
            'Monitor for NTLM relay attack indicators',
            'Consider disabling RPC certificate enrollment if not required'
          ]
        }

        const anomaly = this.createESC11Anomaly(detection, context)
        anomalies.push(anomaly)
      })
    }

    return anomalies
  }

  private detectNTLMUsage(ca: any, context: ADCSContext): boolean {
    // Check for NTLM authentication patterns
    // This could be detected from event logs or CA configuration
    const interfaceFlags = ca.interfaceFlags || 0

    // IF_ENROLLMENT_PROXY might indicate NTLM usage
    return (interfaceFlags & 0x00000020) !== 0
  }

  private findVulnerableTemplates(context: ADCSContext): any[] {
    if (!context.certificateTemplates) return []

    // Templates that are vulnerable when combined with unencrypted requests
    return context.certificateTemplates.filter(template => {
      const hasManagerApproval = (template.enrollmentFlags & 2) !== 0
      const hasClientAuthEKU = template.extendedKeyUsage?.some(eku =>
        ['1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2', '2.5.29.37.0'].includes(eku)
      )

      return !hasManagerApproval && hasClientAuthEKU && template.enabled
    })
  }

  private groupBySourceIP(events: CertificateEvent[]): Record<string, CertificateEvent[]> {
    const groups: Record<string, CertificateEvent[]> = {}

    events.forEach(event => {
      const sourceIP = event.sourceIp || event.rawData?.sourceIP || 'unknown'
      if (!groups[sourceIP]) {
        groups[sourceIP] = []
      }
      groups[sourceIP].push(event)
    })

    return groups
  }

  private findCAForEvents(events: CertificateEvent[], context: ADCSContext): any | null {
    // Try to determine which CA handled these requests
    const caNames = events.map(event => event.certificateAuthority || event.rawData?.certificateAuthority)
    const uniqueCANames = Array.from(new Set(caNames.filter(Boolean)))

    if (uniqueCANames.length === 1 && context.certificateAuthorities) {
      return context.certificateAuthorities.find(ca =>
        ca.name === uniqueCANames[0] || ca.dnsName === uniqueCANames[0]
      )
    }

    return null
  }

  private createESC11Anomaly(
    detection: ESCDetectionResult,
    context: ADCSContext
  ): Anomaly {
    const title = `🚨 ESC11 Vulnerability: ${detection.affectedEntities[0].name}`
    const description = `Unencrypted certificate requests detected for ${detection.affectedEntities[0].name}. ` +
      `RPC certificate requests without encryption are vulnerable to NTLM relay attacks and credential interception.`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: detection.vulnerability,
        severity: detection.severity,
        confidence: detection.confidence,
        affectedEntity: detection.affectedEntities[0].name,
        timeWindow: this.timeWindow,
        detectionMethod: 'certificate_request_analysis',
        evidence: detection.evidence
      },
      detection.confidence,
      {
        attackType: 'ntlm_relay_attack',
        vulnerabilityType: 'ESC11',
        riskLevel: detection.severity
      }
    )
  }
}
