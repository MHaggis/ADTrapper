import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, CertificateEvent, ADCSContext, ESCDetectionResult } from '../types'

export class ESC8Rule extends BaseRule {
  constructor() {
    super({
      id: 'esc8_http_enrollment_detection',
      name: 'ESC8 - HTTP Certificate Enrollment Detection',
      description: 'Detects HTTP certificate enrollment attempts that are vulnerable to interception and relay attacks',
      category: 'security',
      severity: 'medium',
      timeWindow: 60, // 1 hour for enrollment pattern analysis
      thresholds: {
        httpEnrollmentBonus: 2,
        noHttpsBonus: 1,
        suspiciousSourceBonus: 1,
        minHTTPEvents: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects ESC8 vulnerabilities where Certificate Authority (CA) web enrollment is configured to use HTTP instead of HTTPS, making it vulnerable to interception and NTLM relay attacks. HTTP enrollment allows attackers to capture and relay authentication credentials, potentially leading to unauthorized certificate issuance.',
        detectionLogic: 'Analyzes CA web enrollment configurations for HTTP endpoints and monitors certificate enrollment attempts. Detects NTLM authentication usage with HTTP enrollment, which is particularly vulnerable to relay attacks like PetitPotam. Identifies enrollment attempts from suspicious sources that may indicate interception attempts.',
        falsePositives: 'Legitimate HTTP enrollment in internal networks where interception is not a concern, properly secured HTTP enrollment with additional authentication controls, or certificate requests that follow organizational security policies. May also trigger during legitimate certificate renewal or system administration activities.',
        mitigation: [
          'Enable HTTPS-only for CA web enrollment endpoints',
          'Disable HTTP certificate enrollment completely',
          'Configure Extended Protection for Authentication (EPA) on web enrollment',
          'Implement certificate request authentication beyond NTLM',
          'Monitor HTTP certificate enrollment attempts',
          'Use Locksmith to identify and remediate ESC8 vulnerabilities',
          'Configure CA web enrollment to require strong authentication',
          'Implement network-level protection against NTLM relay attacks',
          'Regular AD CS security assessments and configuration audits',
          'Configure certificate enrollment restrictions in Group Policy'
        ],
        windowsEvents: ['4886 (Certificate Services Started)', '4887 (Certificate Issued)', '4888 (Certificate Services Backup Started)', '53 (Certificate Request)', '54 (Certificate Issued)', '4876 (Certificate Services Backup Started)', '4877 (Certificate Services Backup Completed)', '4624 (Account Logon)', '4625 (Account Logon Failed)', '4776 (NTLM Authentication)'],
        exampleQuery: `index=windows EventCode=4887 | stats count by Protocol, AuthenticationType | where Protocol="HTTP"`,
        recommendedThresholds: {
          httpEnrollmentBonus: 2,
          noHttpsBonus: 1,
          suspiciousSourceBonus: 1,
          minHTTPEvents: 1
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    const adcsContext = context as ADCSContext

    // Check for HTTP enrollment endpoints in CA configuration
    const caConfigurationAnomalies = this.analyzeCAWebEnrollment(adcsContext)
    anomalies.push(...caConfigurationAnomalies)

    // Look for HTTP enrollment attempts in events
    const certificateEvents = events.filter(event =>
      this.isCertificateEvent(event)
    ) as CertificateEvent[]

    if (certificateEvents.length > 0) {
      const httpEnrollmentAnomalies = this.analyzeHTTPEnrollments(certificateEvents, adcsContext)
      anomalies.push(...httpEnrollmentAnomalies)
    }

    return anomalies
  }

  private isCertificateEvent(event: AuthEvent): boolean {
    const adcsEventIds = ['4886', '4887', '4888', '53', '54']
    return adcsEventIds.includes(event.eventId) ||
           (event as CertificateEvent).certificateTemplate !== undefined
  }

  private analyzeCAWebEnrollment(context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    if (!context.certificateAuthorities) return anomalies

    context.certificateAuthorities.forEach(ca => {
      // Check if CA has web enrollment enabled
      if (context.adcsConfiguration?.webEnrollmentEnabled) {
        let riskScore = 2 // Base low risk
        let confidence = 75

        // Higher risk if HTTP is enabled without HTTPS
        if (!context.adcsConfiguration.webEnrollmentHttpsOnly) {
          riskScore += this.thresholds.noHttpsBonus
          confidence += 20
        }

        // Check if web enrollment URL is accessible
        const webUrl = context.adcsConfiguration.webEnrollmentUrl
        if (webUrl && webUrl.startsWith('http://')) {
          riskScore += this.thresholds.httpEnrollmentBonus
          confidence += 25
        }

        // Check for NTLM authentication (common with HTTP)
        const usesNTLM = this.detectNTLMAuthentication(ca)
        if (usesNTLM) {
          riskScore += 1
          confidence += 15
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'ESC8',
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
            webEnrollmentEnabled: context.adcsConfiguration?.webEnrollmentEnabled,
            webEnrollmentUrl: context.adcsConfiguration?.webEnrollmentUrl,
            httpsOnly: context.adcsConfiguration?.webEnrollmentHttpsOnly,
            usesNTLM,
            interfaceFlags: ca.interfaceFlags,
            securityFlags: ca.securityFlags
          },
          remediation: [
            'Disable HTTP certificate enrollment endpoints',
            'Enable HTTPS-only certificate enrollment',
            'Implement Extended Protection for Authentication (EPA)',
            'Disable NTLM authentication if possible',
            'Use certificate-based authentication instead of username/password',
            'Restrict web enrollment to authorized networks only'
          ]
        }

        const anomaly = this.createESC8Anomaly(detection, context)
        anomalies.push(anomaly)
      }
    })

    return anomalies
  }

  private analyzeHTTPEnrollments(events: CertificateEvent[], context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    // Look for events that indicate HTTP enrollment usage
    const httpEnrollmentEvents = events.filter(event => {
      // Check event data for HTTP enrollment indicators
      const rawData = event.rawData
      return rawData?.enrollmentMethod === 'http' ||
             rawData?.enrollmentMethod === 'web' ||
             rawData?.protocol === 'http' ||
             rawData?.url?.startsWith('http://') ||
             event.rawData?.requestType === 'web_enrollment'
    })

    if (httpEnrollmentEvents.length >= this.thresholds.minHTTPEvents) {
      // Group by source IP to identify patterns
      const sourceGroups = this.groupBySourceIP(httpEnrollmentEvents)

      Object.entries(sourceGroups).forEach(([sourceIP, sourceEvents]) => {
        const ipInfo = context.ipIntelligence?.find(ip => ip.ip === sourceIP)
        const isSuspiciousSource = ipInfo && (
          ipInfo.isVpn || ipInfo.isMalicious || ipInfo.riskScore > 70
        )

        let riskScore = 2
        let confidence = 70

        if (isSuspiciousSource) {
          riskScore += this.thresholds.suspiciousSourceBonus
          confidence += 20
        }

        if (sourceEvents.length > 5) {
          riskScore += 1
          confidence += 15
        }

        // Check if HTTP enrollment is actually enabled on CA
        const hasHTTPEnrollment = context.adcsConfiguration?.webEnrollmentEnabled &&
                                 !context.adcsConfiguration.webEnrollmentHttpsOnly

        if (hasHTTPEnrollment) {
          riskScore += this.thresholds.httpEnrollmentBonus
          confidence += 25
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'ESC8',
          severity: riskScore >= 4 ? 'high' : riskScore >= 3 ? 'medium' : 'low',
          confidence: Math.min(confidence, 100),
          affectedEntities: [
            {
              type: 'ip',
              id: sourceIP,
              name: sourceIP
            }
          ],
          evidence: {
            sourceIP,
            httpEnrollmentEvents: sourceEvents.length,
            isSuspiciousSource,
            ipIntelligence: ipInfo,
            enrollmentMethods: Array.from(new Set(sourceEvents.map(e => e.rawData?.enrollmentMethod).filter(Boolean))),
            certificateTemplates: Array.from(new Set(sourceEvents.map(e => e.certificateTemplate).filter(Boolean))),
            hasHTTPEnrollmentEnabled: hasHTTPEnrollment,
            sampleEvents: sourceEvents.slice(0, 5).map(event => ({
              timestamp: event.timestamp,
              userName: event.userName,
              template: event.certificateTemplate,
              enrollmentMethod: event.rawData?.enrollmentMethod
            }))
          },
          remediation: [
            'Disable HTTP certificate enrollment',
            'Enforce HTTPS-only enrollment',
            'Implement network segmentation for enrollment endpoints',
            'Enable EPA (Extended Protection for Authentication)',
            'Monitor enrollment traffic for suspicious patterns',
            'Consider using certificate-based authentication'
          ]
        }

        const anomaly = this.createESC8Anomaly(detection, context)
        anomalies.push(anomaly)
      })
    }

    return anomalies
  }

  private detectNTLMAuthentication(ca: any): boolean {
    // Check CA configuration for NTLM usage
    // This would typically check registry settings or event logs
    // For now, we'll check interface flags and security settings
    const interfaceFlags = ca.interfaceFlags || 0
    const securityFlags = ca.securityFlags || 0

    // IF_ENROLLMENT_PROXY flag might indicate NTLM usage
    return (interfaceFlags & 0x00000020) !== 0 ||
           (securityFlags & 0x00000001) !== 0 // Hypothetical NTLM flag
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

  private createESC8Anomaly(
    detection: ESCDetectionResult,
    context: ADCSContext
  ): Anomaly {
    const title = `🚨 ESC8 Vulnerability: ${detection.affectedEntities[0].name}`
    const description = `HTTP certificate enrollment detected for ${detection.affectedEntities[0].name}. ` +
      `HTTP enrollment is vulnerable to interception, relay attacks, and credential theft.`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: detection.vulnerability,
        severity: detection.severity,
        confidence: detection.confidence,
        affectedEntity: detection.affectedEntities[0].name,
        timeWindow: this.timeWindow,
        detectionMethod: 'enrollment_protocol_analysis',
        evidence: detection.evidence
      },
      detection.confidence,
      {
        attackType: 'http_enrollment_interception',
        vulnerabilityType: 'ESC8',
        riskLevel: detection.severity
      }
    )
  }
}
