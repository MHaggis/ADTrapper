import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, ESCDetectionResult } from '../types'

export class CertificateAuthenticationCorrelationRule extends BaseRule {
  constructor() {
    super({
      id: 'certificate_auth_correlation',
      name: 'Certificate Authentication Correlation',
      description: 'Detects correlations between certificate issuance and authentication events',
      category: 'security',
      severity: 'medium',
      timeWindow: 30, // 30 minutes for correlation analysis
      thresholds: {
        correlationThreshold: 1,
        thumbprintMatchBonus: 2,
        rapidCorrelationBonus: 1,
        timeWindowMinutes: 5
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects correlations between certificate issuance and authentication events to identify certificate-based attacks and privilege escalation. Monitors the certificate lifecycle from issuance to usage, identifying suspicious patterns where certificates are issued and immediately used for authentication.',
        detectionLogic: 'Correlates certificate issuance events with authentication events within configurable time windows. Analyzes certificate thumbprint matches, rapid certificate-to-authentication correlations, and patterns of certificate abuse for privilege escalation or unauthorized access.',
        falsePositives: 'Legitimate certificate-based authentication workflows, automated certificate renewals, system services using certificates, or legitimate certificate issuance followed by immediate use. May also trigger during certificate deployment or system configuration activities.',
        mitigation: [
          'Implement certificate request approval workflows',
          'Monitor certificate issuance and usage patterns',
          'Enable certificate-based authentication logging',
          'Implement certificate revocation monitoring',
          'Use short-lived certificates where possible',
          'Configure certificate authentication restrictions',
          'Monitor for certificate thumbprint reuse',
          'Implement certificate inventory management',
          'Enable Smart Card removal policies',
          'Regular certificate audit and compliance review'
        ],
        windowsEvents: ['4887 (Certificate Issued)', '4768 (Kerberos TGT Requested)', '4624 (Successful Logon)', '4769 (Kerberos Service Ticket Requested)', '4770 (Kerberos Service Ticket Renewed)', '4886 (Certificate Services Started)', '4888 (Certificate Services Backup Started)', '54 (Certificate Issued)', '4870 (Certificate Services Published)'],
        exampleQuery: `index=windows EventCode=4887 OR EventCode=4768 | transaction TargetUserName maxspan=5m | where eventcount > 1`,
        recommendedThresholds: {
          correlationThreshold: 1,
          thumbprintMatchBonus: 2,
          rapidCorrelationBonus: 1,
          timeWindowMinutes: 5
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Look for authentication events (4768 - Kerberos TGT)
    const authEvents = events.filter(event =>
      event.eventId === '4768' || // Kerberos TGT request
      event.eventId === '4624' || // Successful logon
      event.rawData?.operation === 'authentication' ||
      event.rawData?.operation === 'kerberos_auth'
    )

    // Look for certificate-related events (4887 - Certificate issued)
    const certEvents = events.filter(event =>
      event.eventId === '4887' || // Certificate issued
      event.rawData?.certificateThumbprint ||
      event.rawData?.certificateSerialNumber ||
      event.rawData?.operation === 'certificate_issued'
    )

    // Find correlations between certificate issuance and authentication
    const correlations: Array<{
      userName: string
      certificateEvent: AuthEvent
      authEvent: AuthEvent
      timeDiff: number
      thumbprintMatch: boolean
    }> = []

    certEvents.forEach(certEvent => {
      const certUser = certEvent.userName || certEvent.rawData?.userName
      if (!certUser) return

      const relatedAuth = authEvents.find(authEvent => {
        const authUser = authEvent.userName || authEvent.rawData?.userName
        if (authUser !== certUser) return false

        const timeDiff = Math.abs(
          new Date(authEvent.timestamp).getTime() - new Date(certEvent.timestamp).getTime()
        )
        const timeWindowMs = this.thresholds.timeWindowMinutes * 60 * 1000 // Convert to milliseconds
        return timeDiff <= timeWindowMs
      })

      if (relatedAuth) {
        // Check for thumbprint match
        const certThumbprint = certEvent.rawData?.certificateThumbprint
        const authThumbprint = relatedAuth.rawData?.certificateThumbprint
        const thumbprintMatch = certThumbprint && authThumbprint === certThumbprint

        correlations.push({
          userName: certUser,
          certificateEvent: certEvent,
          authEvent: relatedAuth,
          timeDiff: Math.abs(
            new Date(relatedAuth.timestamp).getTime() - new Date(certEvent.timestamp).getTime()
          ),
          thumbprintMatch
        })
      }
    })

    if (correlations.length >= this.thresholds.correlationThreshold) {
      // Group by user
      const correlationsByUser = new Map<string, typeof correlations>()

      correlations.forEach(correlation => {
        if (!correlationsByUser.has(correlation.userName)) {
          correlationsByUser.set(correlation.userName, [])
        }
        correlationsByUser.get(correlation.userName)!.push(correlation)
      })

      // Analyze each user's correlation patterns
      for (const [userName, userCorrelations] of Array.from(correlationsByUser.entries())) {
        let riskScore = 2 // Base medium risk for correlation
        let confidence = 70

        // Check for certificate thumbprint matches (high confidence indicator)
        const thumbprintMatches = userCorrelations.filter(c => c.thumbprintMatch)
        if (thumbprintMatches.length > 0) {
          riskScore += this.thresholds.thumbprintMatchBonus
          confidence += 30
        }

        // Check for rapid correlations (suspicious timing)
        const rapidCorrelations = userCorrelations.filter(c =>
          c.timeDiff <= (2 * 60 * 1000) // Within 2 minutes
        )
        if (rapidCorrelations.length > 0) {
          riskScore += this.thresholds.rapidCorrelationBonus
          confidence += 15
        }

        // Check for unusual authentication patterns
        const unusualPatterns = this.detectUnusualPatterns(userCorrelations)
        if (unusualPatterns.hasUnusualPatterns) {
          riskScore += 1
          confidence += 10
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'Certificate Authentication Correlation' as any,
          severity: riskScore >= 4 ? 'high' : riskScore >= 3 ? 'medium' : 'low',
          confidence: Math.min(confidence, 100),
          affectedEntities: [
            {
              type: 'user',
              id: userName,
              name: userName
            }
          ],
          evidence: {
            correlations: userCorrelations.length,
            thumbprintMatches: thumbprintMatches.length,
            rapidCorrelations: rapidCorrelations.length,
            unusualPatterns: unusualPatterns.patterns,
            correlationDetails: userCorrelations.map(correlation => ({
              certificateTime: correlation.certificateEvent.timestamp,
              authTime: correlation.authEvent.timestamp,
              timeDiffMinutes: Math.round(correlation.timeDiff / 60000),
              certificateThumbprint: correlation.certificateEvent.rawData?.certificateThumbprint,
              authThumbprint: correlation.authEvent.rawData?.certificateThumbprint,
              thumbprintMatch: correlation.thumbprintMatch,
              authType: correlation.authEvent.eventId,
              certTemplate: correlation.certificateEvent.rawData?.certificateTemplate
            }))
          },
          remediation: [
            'Verify certificate-based authentication legitimacy',
            'Check if certificate was issued for legitimate purposes',
            'Monitor for anomalous authentication patterns',
            'Review certificate thumbprint usage across systems',
            'Consider certificate revocation if compromise is suspected',
            'Audit certificate template usage and permissions'
          ]
        }

        const anomaly = this.createCorrelationAnomaly(detection, context)
        anomalies.push(anomaly)
      }
    }

    return anomalies
  }

  private detectUnusualPatterns(correlations: Array<{
    userName: string
    certificateEvent: AuthEvent
    authEvent: AuthEvent
    timeDiff: number
    thumbprintMatch: boolean
  }>): {
    hasUnusualPatterns: boolean
    patterns: string[]
  } {
    const patterns: string[] = []

    // Check for authentication before certificate issuance (unusual order)
    const authBeforeCert = correlations.filter(c =>
      new Date(c.authEvent.timestamp) < new Date(c.certificateEvent.timestamp)
    )

    if (authBeforeCert.length > correlations.length * 0.7) { // 70% of correlations
      patterns.push('authentication_before_certificate')
    }

    // Check for high-value certificate templates
    const highValueTemplates = correlations.filter(c => {
      const template = c.certificateEvent.rawData?.certificateTemplate || ''
      return template.includes('DomainController') ||
             template.includes('DomainAdmin') ||
             template.includes('EnterpriseAdmin')
    })

    if (highValueTemplates.length > 0) {
      patterns.push('high_value_certificate_templates')
    }

    // Check for unusual authentication types
    const unusualAuthTypes = correlations.filter(c =>
      c.authEvent.eventId === '4624' && // Interactive logon
      c.authEvent.rawData?.logonType === '3' // Network logon
    )

    if (unusualAuthTypes.length > 0) {
      patterns.push('unusual_logon_types')
    }

    // Check for multiple certificates per authentication
    const certsPerAuth = new Map<string, number>()
    correlations.forEach(c => {
      const authKey = `${c.authEvent.timestamp}_${c.authEvent.eventId}`
      certsPerAuth.set(authKey, (certsPerAuth.get(authKey) || 0) + 1)
    })

    const multipleCerts = Array.from(certsPerAuth.values()).filter(count => count > 1)
    if (multipleCerts.length > 0) {
      patterns.push('multiple_certificates_per_auth')
    }

    return {
      hasUnusualPatterns: patterns.length > 0,
      patterns
    }
  }

  private createCorrelationAnomaly(
    detection: ESCDetectionResult,
    context: AnalyticsContext
  ): Anomaly {
    const title = `🔗 Certificate Auth Correlation: ${detection.affectedEntities[0].name}`
    const description = `Certificate issuance and authentication correlation detected for user ${detection.affectedEntities[0].name}. ` +
      `This may indicate certificate-based authentication abuse or Golden Certificate usage.`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: detection.vulnerability,
        severity: detection.severity,
        confidence: detection.confidence,
        affectedEntity: detection.affectedEntities[0].name,
        timeWindow: this.timeWindow,
        detectionMethod: 'certificate_auth_correlation',
        evidence: detection.evidence
      },
      detection.confidence,
      {
        attackType: 'certificate_authentication_correlation',
        vulnerabilityType: detection.vulnerability,
        riskLevel: detection.severity
      }
    )
  }
}
