import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, ESCDetectionResult } from '../types'

export class CABackupRule extends BaseRule {
  constructor() {
    super({
      id: 'ca_backup_detection',
      name: 'CA Backup Detection',
      description: 'Detects Certificate Authority backup operations that may indicate theft or persistence',
      category: 'security',
      severity: 'high',
      timeWindow: 120, // 2 hours for backup pattern analysis
      thresholds: {
        backupThreshold: 1,
        unprivilegedUserBonus: 2,
        multipleBackupsBonus: 1,
        unusualTimingBonus: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects Certificate Authority backup operations that could indicate theft of private keys or persistence mechanisms. CA database backups contain highly sensitive cryptographic material including private keys, which can be used to issue fraudulent certificates or compromise the entire PKI infrastructure.',
        detectionLogic: 'Monitors CA backup operations and analyzes patterns such as unprivileged users performing backups, unusual timing, multiple backup attempts, and suspicious source locations. Correlates backup activities with user privileges and access patterns to identify potential compromise indicators.',
        falsePositives: 'Legitimate CA backup operations performed by authorized administrators, scheduled backup maintenance, disaster recovery procedures, or system migrations. May also trigger during legitimate PKI infrastructure maintenance or certificate authority migrations.',
        mitigation: [
          'Restrict CA backup permissions to essential administrators only',
          'Implement multi-factor authentication for CA management operations',
          'Monitor all CA backup operations with alerting',
          'Use encrypted backup storage with access controls',
          'Implement backup operation approval workflows',
          'Regular review of CA backup access logs',
          'Configure CA backup auditing and monitoring',
          'Use dedicated backup administrator accounts',
          'Implement session recording for CA management',
          'Regular security assessment of backup procedures'
        ],
        windowsEvents: ['4876 (Certificate Services Backup Started)', '4877 (Certificate Services Backup Completed)', '4888 (Certificate Services Backup Started)', '4889 (Certificate Services Restore Started)', '4890 (Certificate Services Backup Completed)', '4891 (Certificate Services Restore Completed)', '4898 (Certificate Template Loaded)', '4899 (Certificate Template Updated)'],
        exampleQuery: `index=windows EventCode=4876 OR EventCode=4877 | stats count by TargetUserName, Computer | where count > 1`,
        recommendedThresholds: {
          backupThreshold: 1,
          unprivilegedUserBonus: 2,
          multipleBackupsBonus: 1,
          unusualTimingBonus: 1
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Look for CA backup operations (Events 4876, 4877)
    const backupEvents = events.filter(event =>
      event.eventId === '4876' || event.eventId === '4877' ||
      event.rawData?.operation === 'ca_backup' ||
      event.rawData?.operation === 'database_backup' ||
      event.rawData?.operation === 'certificate_backup'
    )

    if (backupEvents.length >= this.thresholds.backupThreshold) {
      // Group by user
      const backupByUser = new Map<string, AuthEvent[]>()

      backupEvents.forEach(event => {
        const userKey = event.userName || event.rawData?.userName || 'unknown'
        if (!backupByUser.has(userKey)) {
          backupByUser.set(userKey, [])
        }
        backupByUser.get(userKey)!.push(event)
      })

      // Analyze each user's backup activity
      for (const [userName, userBackups] of Array.from(backupByUser.entries())) {
        let riskScore = 3 // Base high risk for CA backup operations
        let confidence = 75

        // Check if user is privileged
        const userProfile = context.userProfiles?.find(u =>
          u.userName === userName || u.groups?.includes(userName)
        )

        if (!userProfile?.privileged) {
          riskScore += this.thresholds.unprivilegedUserBonus // Very suspicious if non-privileged user backs up CA
          confidence += 25
        }

        // Check for multiple backups (suspicious pattern)
        if (userBackups.length > 2) {
          riskScore += this.thresholds.multipleBackupsBonus
          confidence += 15
        }

        // Check for unusual timing
        const unusualTiming = this.detectUnusualTiming(userBackups)
        if (unusualTiming) {
          riskScore += this.thresholds.unusualTimingBonus
          confidence += 10
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'CA Database Backup' as any,
          severity: riskScore >= 5 ? 'critical' : 'high',
          confidence: Math.min(confidence, 100),
          affectedEntities: [
            {
              type: 'user',
              id: userName,
              name: userName
            }
          ],
          evidence: {
            backupOperations: userBackups.length,
            isPrivilegedUser: userProfile?.privileged || false,
            unusualTiming,
            backupDetails: userBackups.map(event => ({
              timestamp: event.timestamp,
              eventId: event.eventId,
              computer: event.computerName,
              operation: event.rawData?.operation || 'ca_backup',
              backupType: this.getBackupType(event)
            }))
          },
          remediation: [
            'Investigate CA backup operations for legitimacy',
            'Verify backup was authorized and necessary',
            'Check backup contents for sensitive certificate data',
            'Review user permissions for CA backup operations',
            'Consider implementing backup approval workflow',
            'Monitor for unauthorized CA database access',
            'Audit backup destination and ensure secure storage'
          ]
        }

        const anomaly = this.createCABackupAnomaly(detection, context)
        anomalies.push(anomaly)
      }
    }

    return anomalies
  }

  private detectUnusualTiming(events: AuthEvent[]): boolean {
    if (events.length < 2) return false

    // Check if backups occurred outside normal business hours
    const unusualHours = events.filter(event => {
      const hour = new Date(event.timestamp).getHours()
      return hour < 6 || hour > 18 // Outside 6 AM - 6 PM
    })

    // Check if backups occurred on weekends
    const weekendBackups = events.filter(event => {
      const day = new Date(event.timestamp).getDay()
      return day === 0 || day === 6 // Sunday or Saturday
    })

    // Check for rapid backups (suspicious pattern)
    const rapidBackups = this.detectRapidBackups(events)

    return unusualHours.length > 0 || weekendBackups.length > 0 || rapidBackups
  }

  private detectRapidBackups(events: AuthEvent[]): boolean {
    if (events.length < 2) return false

    const timestamps = events.map(e => new Date(e.timestamp).getTime()).sort()
    const intervals = []

    for (let i = 1; i < timestamps.length; i++) {
      intervals.push(timestamps[i] - timestamps[i - 1])
    }

    // Check for backups within 1 hour of each other
    return intervals.some(interval => interval < 3600000) // 1 hour in milliseconds
  }

  private getBackupType(event: AuthEvent): string {
    const eventId = event.eventId
    const operation = event.rawData?.operation || ''

    if (eventId === '4876') return 'Backup Started'
    if (eventId === '4877') return 'Backup Completed'
    if (operation.includes('cert')) return 'Certificate Backup'
    if (operation.includes('database')) return 'Database Backup'
    if (operation.includes('key')) return 'Key Backup'

    return 'Unknown Backup Type'
  }

  private createCABackupAnomaly(
    detection: ESCDetectionResult,
    context: AnalyticsContext
  ): Anomaly {
    const title = `🚨 CA Backup Operation: ${detection.affectedEntities[0].name}`
    const description = `Certificate Authority backup operations detected for user ${detection.affectedEntities[0].name}. ` +
      `CA backups may contain sensitive certificate data and private keys.`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: detection.vulnerability,
        severity: detection.severity,
        confidence: detection.confidence,
        affectedEntity: detection.affectedEntities[0].name,
        timeWindow: this.timeWindow,
        detectionMethod: 'ca_backup_detection',
        evidence: detection.evidence
      },
      detection.confidence,
      {
        attackType: 'ca_backup_operation',
        vulnerabilityType: detection.vulnerability,
        riskLevel: detection.severity
      }
    )
  }
}
