import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, ESCDetectionResult } from '../types'

export class CertificateExportRule extends BaseRule {
  constructor() {
    super({
      id: 'certificate_export_detection',
      name: 'Certificate Export Detection',
      description: 'Detects certificate export operations that may indicate theft or unauthorized access',
      category: 'security',
      severity: 'high',
      timeWindow: 60, // 1 hour for export pattern analysis
      thresholds: {
        exportThreshold: 1,
        rapidExportsThreshold: 5,
        unusualLocationBonus: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects certificate export operations that may indicate theft, unauthorized access, or certificate-based attacks. Certificate exports containing private keys can be used for privilege escalation, impersonation attacks, or lateral movement within Active Directory environments.',
        detectionLogic: 'Monitors certificate export events and analyzes patterns such as unprivileged users exporting certificates, rapid export sequences, and unusual export locations. Correlates export activities with user privileges and access patterns to identify potential certificate theft or abuse scenarios.',
        falsePositives: 'Legitimate certificate exports for backup, migration, system administration, or legitimate certificate renewal processes. May also trigger during certificate lifecycle management or automated certificate deployment activities.',
        mitigation: [
          'Implement strict certificate export controls and approval workflows',
          'Monitor all certificate export operations with alerting',
          'Restrict certificate export permissions to essential users only',
          'Use certificate export logging and auditing',
          'Implement certificate export encryption and access controls',
          'Regular review of exported certificates and their usage',
          'Configure certificate export restrictions in Group Policy',
          'Use certificate-based authentication with export restrictions',
          'Monitor for certificate export from suspicious locations',
          'Implement certificate inventory and tracking systems'
        ],
        windowsEvents: ['1007 (Certificate Exported)', '4888 (Certificate Services Backup Started)', '4889 (Certificate Services Restore Started)', '4890 (Certificate Services Backup Completed)', '4891 (Certificate Services Restore Completed)', '4876 (Certificate Services Backup Started)', '4877 (Certificate Services Backup Completed)'],
        exampleQuery: `index=windows EventCode=1007 | stats count by TargetUserName, Computer | where count > 3`,
        recommendedThresholds: {
          exportThreshold: 1,
          rapidExportsThreshold: 5,
          unusualLocationBonus: 1
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Look for certificate export events (Event 1007)
    const exportEvents = events.filter(event =>
      event.eventId === '1007' || // CertificateServicesClient export event
      event.rawData?.operation === 'certificate_export' ||
      event.rawData?.operation === 'pfx_export'
    )

    if (exportEvents.length >= this.thresholds.exportThreshold) {
      // Group by user
      const exportByUser = new Map<string, AuthEvent[]>()

      exportEvents.forEach(event => {
        const userKey = event.userName || event.rawData?.userName || 'unknown'
        if (!exportByUser.has(userKey)) {
          exportByUser.set(userKey, [])
        }
        exportByUser.get(userKey)!.push(event)
      })

      // Analyze each user's export activity
      for (const [userName, userExports] of Array.from(exportByUser.entries())) {
        let riskScore = 3 // Base high risk for certificate exports
        let confidence = 80

        // Check if user is privileged (higher risk if not)
        const userProfile = context.userProfiles?.find(u =>
          u.userName === userName || u.groups?.includes(userName)
        )

        if (!userProfile?.privileged) {
          riskScore += 1
          confidence += 10
        }

        // Check for rapid exports (suspicious pattern)
        if (userExports.length > this.thresholds.rapidExportsThreshold) {
          riskScore += 1
          confidence += 15
        }

        // Check for unusual export patterns
        const unusualPatterns = this.detectUnusualExportPatterns(userExports)
        if (unusualPatterns.hasUnusualPatterns) {
          riskScore += this.thresholds.unusualLocationBonus
          confidence += 10
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'Certificate Export' as any,
          severity: riskScore >= 5 ? 'critical' : riskScore >= 4 ? 'high' : 'medium',
          confidence: Math.min(confidence, 100),
          affectedEntities: [
            {
              type: 'user',
              id: userName,
              name: userName
            }
          ],
          evidence: {
            exportEvents: userExports.length,
            isPrivilegedUser: userProfile?.privileged || false,
            unusualPatterns: unusualPatterns.patterns,
            exportDetails: userExports.map(event => ({
              timestamp: event.timestamp,
              computer: event.computerName,
              operation: event.rawData?.operation || 'certificate_export',
              subjectName: event.rawData?.subjectName,
              exportLocation: event.rawData?.exportPath || 'unknown'
            }))
          },
          remediation: [
            'Immediately investigate certificate export activities',
            'Review exported certificates for unauthorized access',
            'Check if certificates were exported for legitimate purposes',
            'Consider revoking exported certificates if compromise is suspected',
            'Enable enhanced monitoring for certificate export operations',
            'Implement approval workflow for certificate exports'
          ]
        }

        const anomaly = this.createCertificateExportAnomaly(detection, context)
        anomalies.push(anomaly)
      }
    }

    return anomalies
  }

  private detectUnusualExportPatterns(events: AuthEvent[]): {
    hasUnusualPatterns: boolean
    patterns: string[]
  } {
    const patterns: string[] = []

    // Check for rapid exports
    if (events.length >= this.thresholds.rapidExportsThreshold) {
      const timestamps = events.map(e => new Date(e.timestamp).getTime()).sort()
      const intervals = []
      for (let i = 1; i < timestamps.length; i++) {
        intervals.push(timestamps[i] - timestamps[i - 1])
      }
      const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length
      if (avgInterval < 300000) { // Less than 5 minutes between exports
        patterns.push('rapid_exports')
      }
    }

    // Check for unusual export locations
    const unusualPaths = events.filter(event => {
      const path = event.rawData?.exportPath || event.rawData?.filePath || ''
      return path.includes('temp') || path.includes('downloads') ||
             path.includes('desktop') || path.includes('recycle')
    })

    if (unusualPaths.length > 0) {
      patterns.push('unusual_export_locations')
    }

    // Check for network paths (suspicious)
    const networkPaths = events.filter(event => {
      const path = event.rawData?.exportPath || event.rawData?.filePath || ''
      return path.startsWith('\\\\') || path.includes('share')
    })

    if (networkPaths.length > 0) {
      patterns.push('network_export_locations')
    }

    return {
      hasUnusualPatterns: patterns.length > 0,
      patterns
    }
  }

  private createCertificateExportAnomaly(
    detection: ESCDetectionResult,
    context: AnalyticsContext
  ): Anomaly {
    const title = `🚨 Certificate Export: ${detection.affectedEntities[0].name}`
    const description = `Certificate export operations detected for user ${detection.affectedEntities[0].name}. ` +
      `Multiple certificate exports may indicate theft or unauthorized access.`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: detection.vulnerability,
        severity: detection.severity,
        confidence: detection.confidence,
        affectedEntity: detection.affectedEntities[0].name,
        timeWindow: this.timeWindow,
        detectionMethod: 'certificate_export_detection',
        evidence: detection.evidence
      },
      detection.confidence,
      {
        attackType: 'certificate_export',
        vulnerabilityType: detection.vulnerability,
        riskLevel: detection.severity
      }
    )
  }
}
